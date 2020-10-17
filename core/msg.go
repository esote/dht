package core

import (
	"crypto/ed25519"
	"errors"
	"io"
	"math"
	"time"

	"github.com/esote/dht/core/crypto"
)

func (msg *Message) MarshalFixed(priv, targetPubl []byte) ([]byte, error) {
	data := make([]byte, FixedMessageSize)
	b := data

	if _, ok := SupportedVersions[msg.Version]; !ok {
		return nil, errors.New("unsupported version")
	}
	b[0] = msg.Version
	b = b[1:]

	switch msg.BodyKind {
	case KindFixed:
	default:
		return nil, errors.New("unsupported body kind")
	}
	b[0] = msg.BodyKind
	b = b[1:]

	header, err := msg.Hdr.MarshalBinary()
	if err != nil {
		return nil, err
	}

	fixed, ok := msg.Payload.(FixedPayload)
	if !ok {
		return nil, errors.New("payload type invalid")
	}
	payload, err := fixed.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Zero-padding is implicit in uninitialized buffer space.
	plain := make([]byte, FixedCiphertextSize-SigSize, FixedCiphertextSize)
	b = plain

	copy(b, header)
	b = b[len(header):]

	copy(b, payload)
	b = b[len(payload):]

	// Sign (header || payload || padding)
	sig := ed25519.Sign(priv, plain)
	plain = append(plain, sig...)

	xpubl, err := crypto.PublEd25519ToX25519(targetPubl)
	if err != nil {
		return nil, err
	}

	ciphertext, err := crypto.EncryptFixed(plain, xpubl)
	if err != nil {
		return nil, err
	}

	if len(data)-PreBodySize != len(ciphertext) {
		return nil, errors.New("ciphertext positioning invalid")
	}
	copy(data[PreBodySize:], ciphertext)

	return data, nil
}

func (msg *Message) UnmarshalFixed(data, priv []byte) error {
	if len(data) < FixedMessageSize {
		return errors.New("message truncated")
	}

	msg.Version = data[0]
	data = data[1:]

	if _, ok := SupportedVersions[msg.Version]; !ok {
		return errors.New("unsupported version")
	}

	msg.BodyKind = data[0]
	data = data[1:]

	switch msg.BodyKind {
	case KindFixed:
	default:
		return errors.New("body kind invalid")
	}

	xpriv, err := crypto.PrivEd25519ToX25519(priv)
	if err != nil {
		return err
	}

	plain, err := crypto.DecryptFixed(data, xpriv)
	if err != nil {
		return err
	}

	if len(plain) < SigSize {
		return errors.New("plaintext body truncated")
	}
	plain, sig := plain[:len(plain)-SigSize], plain[len(plain)-SigSize:]

	msg.Hdr = new(Header)
	if err = msg.Hdr.UnmarshalBinary(plain); err != nil {
		return err
	}
	if msg.Hdr.Time > uint64(math.MaxInt64) {
		return errors.New("header time too large")
	}
	if time.Unix(int64(msg.Hdr.Time), 0).Before(time.Now().UTC()) {
		return errors.New("message expired")
	}
	if !ed25519.Verify(msg.Hdr.NodeID, plain, sig) {
		return errors.New("signature invalid")
	}
	plain = plain[HeaderSize:]

	if !VerifyNodeID(msg.Hdr.NodeID, msg.Hdr.PuzDynX) {
		return errors.New("message node ID invalid")
	}

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
		return errors.New("message type unsupported")
	}
	payload, ok := msg.Payload.(FixedPayload)
	if !ok {
		return errors.New("payload type not fixed")
	}
	n, err := payload.UnmarshalBinaryN(plain)
	if err != nil {
		return err
	}
	plain = plain[n:]

	for i := range plain {
		if plain[i] != 0 {
			return errors.New("padding invalid")
		}
	}

	return nil
}

func (msg *Message) MarshalStream(w io.Writer, priv, targetPubl []byte) error {
	data := make([]byte, PreBodySize)
	b := data

	if _, ok := SupportedVersions[msg.Version]; !ok {
		return errors.New("unsupported version")
	}
	b[0] = msg.Version
	b = b[1:]

	switch msg.BodyKind {
	case KindStream:
	default:
		return errors.New("unsupported body kind")
	}
	b[0] = msg.BodyKind
	b = b[1:]

	if _, err := w.Write(data); err != nil {
		return err
	}

	xpubl, err := crypto.PublEd25519ToX25519(targetPubl)
	if err != nil {
		return err
	}

	wc, err := crypto.NewWriter(w, xpubl, StreamCiphertextBlockSize)
	if err != nil {
		return err
	}

	header, err := msg.Hdr.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err = wc.Write(header); err != nil {
		return err
	}

	sig := ed25519.Sign(priv, header)
	if _, err = wc.Write(sig); err != nil {
		return err
	}

	stream, ok := msg.Payload.(StreamPayload)
	if !ok {
		return errors.New("payload type invalid")
	}
	if err = stream.MarshalStream(wc); err != nil {
		return err
	}

	return wc.Close()
}

func (msg *Message) UnmarshalStream(r io.Reader, priv []byte) error {
	data := make([]byte, PreBodySize)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}

	msg.Version = data[0]
	data = data[1:]

	if _, ok := SupportedVersions[msg.Version]; !ok {
		return errors.New("unsupported version")
	}

	msg.BodyKind = data[0]
	data = data[1:]

	switch msg.BodyKind {
	case KindStream:
	default:
		return errors.New("body kind invalid")
	}

	xpriv, err := crypto.PrivEd25519ToX25519(priv)
	if err != nil {
		return err
	}

	r, err = crypto.NewReader(r, xpriv, StreamCiphertextBlockSize)
	if err != nil {
		return err
	}

	data = make([]byte, HeaderSize+SigSize)
	if _, err = io.ReadFull(r, data); err != nil {
		return err
	}
	header, sig := data[:HeaderSize], data[HeaderSize:]
	msg.Hdr = new(Header)
	if err = msg.Hdr.UnmarshalBinary(header); err != nil {
		return err
	}
	if msg.Hdr.Time > uint64(math.MaxInt64) {
		return errors.New("header time too large")
	}
	if time.Unix(int64(msg.Hdr.Time), 0).Before(time.Now().UTC()) {
		return errors.New("message expired")
	}
	if !ed25519.Verify(msg.Hdr.NodeID, header, sig) {
		return errors.New("signature invalid")
	}

	switch msg.Hdr.MsgType {
	case TypeData:
		msg.Payload = new(DataPayload)
	default:
		return errors.New("message type unsupported")
	}
	stream, ok := msg.Payload.(StreamPayload)
	if !ok {
		return errors.New("payload type not stream")
	}
	if err = stream.UnmarshalStream(r); err != nil {
		return err
	}

	return nil
}
