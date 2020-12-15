package core

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"io/ioutil"
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

	value = "value"
	key   []byte
)

func init() {
	hash := sha512.Sum512([]byte(value))
	key = hash[:]
}

func TestIdempotence(t *testing.T) {
	tests := []MessagePayload{
		&PingPayload{},
		&StorePayload{
			Key:    key,
			Length: uint64(len(value)),
		},
		&DataPayload{
			Length: uint64(len(value)),
			Value:  strings.NewReader(value),
		},
		&FindNodePayload{
			Count:  3,
			Target: publ,
		},
		&FindNodeRespPayload{
			Nodes: []*NodeTriple{{
				ID:   publ,
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 9000,
			}},
		},
		&FindValuePayload{
			Key: key,
		},
		&ErrorPayload{
			Msg: []byte("error!"),
		},
	}

	rpcid := make([]byte, RPCIDSize)
	if _, err := rand.Read(rpcid); err != nil {
		t.Fatal(err)
	}

	msg1 := &Message{
		Version: Version,
		Hdr: &Header{
			NetworkID: []byte{0, 0, 0, 1},
			ID:        publ,
			PuzDynX:   dynX,
			IP:        net.IPv4(127, 0, 0, 1),
			Port:      9000,
			RPCID:     rpcid,
		},
	}

	for i, test := range tests {
		msg1.BodyKind = test.BodyKind()
		msg1.Hdr.MsgType = test.MsgType()
		msg1.Hdr.Time = uint64(time.Now().Add(time.Second).Unix())
		msg1.Payload = test

		var msg2 Message
		switch msg1.BodyKind {
		case KindFixed:
			data, err := msg1.MarshalFixed(priv, publ)
			if err != nil {
				t.Fatalf("test %d: %s", i, err)
			}
			if err = msg2.UnmarshalFixed(data, priv); err != nil {
				t.Fatalf("test %d: %s", i, err)
			}
		case KindStream:
			var b bytes.Buffer
			if err := msg1.MarshalStream(&b, priv, publ); err != nil {
				t.Fatalf("test %d: %s", i, err)
			}
			if err := msg2.UnmarshalStream(&b, priv); err != nil {
				t.Fatalf("test %d: %s", i, err)
			}
		default:
			t.Fatalf("test %d: unexpected payload kind %T", i, test)
		}

		if !sameMessage(msg1, &msg2) {
			t.Fatalf("test %d: messages not equal", i)
		}
	}
}

func sameMessage(x, y *Message) bool {
	// Pre-body
	if x == nil || y == nil {
		return false
	}
	if x.Version != y.Version || x.BodyKind != y.BodyKind {
		return false
	}

	// Header
	if x.Hdr == nil || y.Hdr == nil {
		return false
	}
	if x.Hdr.MsgType != y.Hdr.MsgType ||
		!bytes.Equal(x.Hdr.ID, y.Hdr.ID) ||
		!bytes.Equal(x.Hdr.PuzDynX, y.Hdr.PuzDynX) ||
		!x.Hdr.IP.Equal(y.Hdr.IP) ||
		x.Hdr.Port != y.Hdr.Port ||
		!bytes.Equal(x.Hdr.RPCID, y.Hdr.RPCID) ||
		x.Hdr.Time != y.Hdr.Time {
		return false
	}

	// Payload
	if x.Payload == nil || y.Payload == nil {
		return false
	}
	switch xv := x.Payload.(type) {
	case *PingPayload:
		_, ok := y.Payload.(*PingPayload)
		return ok
	case *StorePayload:
		yv, ok := y.Payload.(*StorePayload)
		return ok && bytes.Equal(xv.Key, yv.Key) &&
			xv.Length == yv.Length
	case *DataPayload:
		yv, ok := y.Payload.(*DataPayload)
		if !ok {
			return false
		}
		yvalue, err := ioutil.ReadAll(yv.Value)
		if err != nil {
			return false
		}
		return xv.Length == yv.Length && string(yvalue) == value
	case *FindNodePayload:
		yv, ok := y.Payload.(*FindNodePayload)
		return ok && xv.Count == yv.Count &&
			bytes.Equal(xv.Target, yv.Target)
	case *FindNodeRespPayload:
		yv, ok := y.Payload.(*FindNodeRespPayload)
		if !ok || len(xv.Nodes) != len(yv.Nodes) {
			return false
		}
		for i, n := range xv.Nodes {
			if !bytes.Equal(n.ID, yv.Nodes[i].ID) ||
				!n.IP.Equal(yv.Nodes[i].IP) ||
				n.Port != yv.Nodes[i].Port {
				return false
			}
		}
		return true
	case *FindValuePayload:
		yv, ok := y.Payload.(*FindValuePayload)
		return ok && bytes.Equal(xv.Key, yv.Key)
	case *ErrorPayload:
		yv, ok := y.Payload.(*ErrorPayload)
		return ok && bytes.Equal(xv.Msg, yv.Msg)
	default:
		return false
	}
}
