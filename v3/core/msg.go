package core

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"

	"github.com/esote/dht/v3/core/crypto"
)

var SupportedVersions = map[uint8]bool{
	0: true,
}

/*
	Steps to read a fixed message:

	1. Read from conn
	2. Read message metadata (vers, etc)
	3. Verify node ID
	4. Decrypt body
	5. Unmarshal header
	6. Unmarshal payload
	7. Verify body signature
	8. Verify padding
*/
func ReadFixedMessage(conn net.PacketConn, priv ed25519.PrivateKey) (*Message, error) {
	buf := make([]byte, FixedMessageSize)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	if n != len(buf) {
		return nil, errors.New("message truncated")
	}

	var msg Message

	msg.Version = buf[0]
	buf = buf[1:]

	if _, ok := SupportedVersions[msg.Version]; ok {
		return nil, fmt.Errorf("unsupported version %d", msg.Version)
	}

	msg.NodeID = make([]byte, NodeIDSize)
	copy(msg.NodeID, buf)
	buf = buf[NodeIDSize:]

	msg.PuzDynX = make([]byte, DynXSize)
	copy(msg.PuzDynX, buf)
	buf = buf[DynXSize:]

	if !VerifyNodeID(msg.NodeID, msg.PuzDynX) {
		return nil, errors.New("message node ID invalid")
	}

	msg.BodyKind = buf[0]
	buf = buf[1:]

	switch msg.BodyKind {
	case KindFixed:
	default:
		return nil, errors.New("body kind invalid")
	}

	xpriv, err := crypto.PrivEd25519ToX25519(priv)
	if err != nil {
		return nil, err
	}

	plain, err := crypto.DecryptFixed(buf, xpriv)
	if err != nil {
		return nil, err
	}
	// keep plain to verify signature
	buf = plain

	if err = msg.Hdr.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	buf = buf[HeaderSize:]

	switch msg.Hdr.MsgType {
	case TypePing:
		msg.Payload = new(PingPayload)
	case TypeStore:
		msg.Payload = new(StorePayload)
	case TypeFindNode:
		msg.Payload = new(FindNodePayload)
	case TypeFindNodeResp:
		msg.Payload = new(FindNodeRespPayload)
	case TypeFindValue:
		msg.Payload = new(FindValuePayload)
	case TypeError:
		msg.Payload = new(ErrorPayload)
	default:
		return nil, errors.New("message type unsupported")
	}
	payload := msg.Payload.(FixedPayload)
	n, err = payload.UnmarshalBinary(buf)
	if err != nil {
		return nil, err
	}
	buf = buf[n:]

	if len(buf) < SigSize {
		return nil, errors.New("signature truncated")
	}
	sig := buf[len(buf)-SigSize:]
	if !ed25519.Verify(msg.NodeID, plain, sig) {
		return nil, errors.New("signature invalid")
	}
	buf = buf[:len(buf)-SigSize]

	for i := range buf {
		if buf[i] != 0 {
			return nil, errors.New("padding invalid")
		}
	}

	return &msg, nil
}
