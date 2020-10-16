package core

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

var (
	publ, _ = hex.DecodeString("527c8ebbe7b7daa6cd0ab162889ccae2cbe29821a" +
		"6b701ea3c0dd0cac39dae71")
	priv, _ = hex.DecodeString("c7bf6ab10b5ec47f3d27c6661c3f5e292bd9986cc" +
		"af3b1a05c33b33d6aa026f4527c8ebbe7b7daa6cd0ab162889ccae2cbe29" +
		"821a6b701ea3c0dd0cac39dae71")
	dynX, _ = hex.DecodeString("58c7d6df2b3b2dd61265476b639a1a647afecdae2" +
		"2493cad3ff6954e843dd8adcf7fc9b272c055cfff2b9b9bae7ab64ac3102" +
		"3349b47189765756579c0bb6ff1")
)

func TestFixed(t *testing.T) {
	rpcid := make([]byte, RPCIDSize)
	if _, err := rand.Read(rpcid); err != nil {
		t.Fatal(err)
	}

	hash := sha512.Sum512(nil)
	l := uint64(3)

	msg1 := Message{
		Version:  Version,
		BodyKind: KindFixed,
		Hdr: &Header{
			MsgType:  TypeStore,
			NodeID:   publ,
			PuzDynX:  dynX,
			NodeIP:   net.IPv4(127, 0, 0, 1),
			NodePort: 9000,
			RPCID:    rpcid,
			Time:     uint64(time.Now().Add(30 * time.Second).Unix()),
		},
		Payload: &StorePayload{
			Key:    hash[:],
			Length: l,
		},
	}

	data, err := msg1.MarshalFixed(priv, publ)
	if err != nil {
		t.Fatal(err)
	}

	var msg2 Message
	if err = msg2.UnmarshalFixed(data, priv); err != nil {
		t.Fatal(err)
	}

	if !sameMessages(&msg1, &msg2) {
		t.Fatal("messages not equal")
	}
	payload, ok := msg2.Payload.(*StorePayload)
	if !ok {
		t.Fatal("incorrect message payload type")
	}
	if !bytes.Equal(payload.Key, hash[:]) || payload.Length != l {
		t.Fatal("payload incorrect")
	}
}

func TestStream(t *testing.T) {
	rpcid := make([]byte, RPCIDSize)
	if _, err := rand.Read(rpcid); err != nil {
		t.Fatal(err)
	}
	data := "wowza"

	msg1 := Message{
		Version:  Version,
		BodyKind: KindStream,
		Hdr: &Header{
			MsgType:  TypeData,
			NodeID:   publ,
			PuzDynX:  dynX,
			NodeIP:   net.IPv4(127, 0, 0, 1),
			NodePort: 9000,
			RPCID:    rpcid,
			Time:     uint64(time.Now().Add(30 * time.Second).Unix()),
		},
		Payload: &DataPayload{
			Length: uint64(len(data)),
			Value:  strings.NewReader(data),
		},
	}

	var b bytes.Buffer
	if err := msg1.MarshalStream(&b, priv, publ); err != nil {
		t.Fatal(err)
	}

	var msg2 Message
	if err := msg2.UnmarshalStream(&b, priv); err != nil {
		t.Fatal(err)
	}
	if !sameMessages(&msg1, &msg2) {
		t.Fatal("messages not equal")
	}
	payload, ok := msg2.Payload.(*DataPayload)
	if !ok {
		t.Fatal("incorrect message payload type")
	}
	if payload.Length != uint64(len(data)) {
		t.Fatal("payload incorrect")
	}
	var s strings.Builder
	if _, err := io.Copy(&s, payload.Value); err != nil {
		t.Fatal(err)
	}
	if s.String() != data {
		t.Fatal("payload incorrect")
	}
}

func sameMessages(msg1, msg2 *Message) bool {
	if msg1 == nil || msg2 == nil {
		return false
	}
	if msg1.Version != msg2.Version ||
		msg1.BodyKind != msg2.BodyKind {
		return false
	}
	if msg1.Hdr == nil || msg2.Hdr == nil {
		return false
	}
	return msg1.Hdr.MsgType == msg2.Hdr.MsgType &&
		bytes.Equal(msg1.Hdr.NodeID, msg2.Hdr.NodeID) &&
		bytes.Equal(msg1.Hdr.PuzDynX, msg2.Hdr.PuzDynX) &&
		msg1.Hdr.NodeIP.Equal(msg2.Hdr.NodeIP) &&
		msg1.Hdr.NodePort == msg2.Hdr.NodePort &&
		bytes.Equal(msg1.Hdr.RPCID, msg2.Hdr.RPCID) &&
		msg1.Hdr.Time == msg2.Hdr.Time
}
