package core

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"

	"github.com/esote/dht/v3/util"
)

const (
	FixedMessageSize = 16384

	RPCIDSize      = 20
	HeaderSize     = 1 + net.IPv6len + 2 + RPCIDSize + 8
	KeySize        = sha512.Size
	NodeIDSize     = ed25519.PublicKeySize
	DynXSize       = sha512.Size
	NodeTripleSize = NodeIDSize + net.IPv6len + 2
	SigSize        = ed25519.SignatureSize

	StorePayloadSize           = KeySize + 8
	FindNodePayloadSize        = 1 + NodeIDSize
	FindNodeRespPayloadMinSize = 1
	FindValuePayloadSize       = KeySize + 8
	ErrorPayloadMinSize        = 1 + 1
)

const (
	KindFixed uint8 = iota
	KindStream
)

const (
	TypePing uint8 = iota
	TypeStore
	TypeData
	TypeFindNode
	TypeFindNodeResp
	TypeFindValue
	TypeError
)

type Message struct {
	Version  uint8
	NodeID   []byte
	PuzDynX  []byte
	BodyKind uint8
	Hdr      *Header
	Payload  MessagePayload
}

type Header struct {
	MsgType  uint8
	NodeIP   net.IP
	NodePort uint16
	RPCID    []byte
	Time     uint64
}

func (hdr *Header) MarshalBinary() ([]byte, error) {
	data := make([]byte, HeaderSize)
	b := data

	b[0] = hdr.MsgType
	b = b[1:]

	ip := hdr.NodeIP.To16()
	if ip == nil {
		return nil, errors.New("node IP invalid")
	}
	copy(b, ip)
	b = b[net.IPv6len:]

	binary.BigEndian.PutUint16(b, hdr.NodePort)
	b = b[2:]

	if len(hdr.RPCID) != RPCIDSize {
		return nil, errors.New("RPCID invalid")
	}
	copy(b, hdr.RPCID)
	b = b[RPCIDSize:]

	binary.BigEndian.PutUint64(b, hdr.Time)
	b = b[8:]

	return data, nil
}

func (hdr *Header) UnmarshalBinary(data []byte) error {
	if len(data) < HeaderSize {
		return errors.New("truncated header")
	}

	hdr.MsgType = data[0]
	data = data[1:]

	hdr.NodeIP = make([]byte, net.IPv6len) // TODO: if .To4, use that?
	copy(hdr.NodeIP, data)
	data = data[net.IPv6len:]

	hdr.NodePort = binary.BigEndian.Uint16(data)
	data = data[2:]

	hdr.RPCID = make([]byte, RPCIDSize)
	copy(hdr.RPCID, data)
	data = data[RPCIDSize:]

	hdr.Time = binary.BigEndian.Uint64(data)
	data = data[8:]

	return nil
}

type MessagePayload interface {
}

type FixedPayload interface {
	MarshalBinary() (data []byte, err error)
	UnmarshalBinary(data []byte) (n int, err error)
}

type StreamPayload interface {
	MarshalStream(w io.Writer) (err error)
	UnmarshalStream(r io.Reader) (err error)
}

type PingPayload struct {
}

var _ FixedPayload = &PingPayload{}

func (ping *PingPayload) MarshalBinary() ([]byte, error) {
	return []byte{}, nil
}

func (ping *PingPayload) UnmarshalBinary(data []byte) (int, error) {
	return 0, nil
}

type StorePayload struct {
	Key    []byte
	Length uint64
}

var _ FixedPayload = &StorePayload{}

func (store *StorePayload) MarshalBinary() ([]byte, error) {
	data := make([]byte, StorePayloadSize)
	b := data

	if len(store.Key) != KeySize {
		return nil, errors.New("key invalid")
	}
	copy(b, store.Key)
	b = b[KeySize:]

	binary.BigEndian.PutUint64(b, store.Length)
	b = b[8:]

	return data, nil
}

func (store *StorePayload) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < StorePayloadSize {
		return 0, errors.New("payload truncated")
	}

	store.Key = make([]byte, KeySize)
	copy(store.Key, data)
	data = data[KeySize:]

	store.Length = binary.BigEndian.Uint64(data)
	data = data[8:]

	return StorePayloadSize, nil
}

type DataPayload struct {
	Length uint64
	Value  io.Reader
}

var _ StreamPayload = &DataPayload{}

func (data *DataPayload) MarshalStream(w io.Writer) error {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, data.Length)
	if _, err := w.Write(b); err != nil {
		return err
	}
	_, err := util.CopyN(w, data.Value, data.Length)
	return err
}

func (data *DataPayload) UnmarshalStream(r io.Reader) error {
	b := make([]byte, 8)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	data.Length = binary.BigEndian.Uint64(b)
	data.Value = util.NewLimitedReader(r, data.Length)
	return nil
}

type FindNodePayload struct {
	Count  uint8
	Target []byte
}

var _ FixedPayload = &FindNodePayload{}

func (fnode *FindNodePayload) MarshalBinary() ([]byte, error) {
	data := make([]byte, FindNodePayloadSize)
	b := data

	b[0] = fnode.Count
	b = b[1:]

	if len(fnode.Target) != NodeIDSize {
		return nil, errors.New("target ID invalid")
	}
	copy(b, fnode.Target)
	b = b[NodeIDSize:]

	return data, nil
}

func (fnode *FindNodePayload) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < FindNodePayloadSize {
		return 0, errors.New("payload truncated")
	}

	fnode.Count = data[0]
	data = data[1:]

	fnode.Target = make([]byte, NodeIDSize)
	copy(fnode.Target, data)
	data = data[NodeIDSize:]

	return FindNodePayloadSize, nil
}

type NodeTriple struct {
	NodeID   []byte
	NodeIP   net.IP
	NodePort uint16
}

type FindNodeRespPayload struct {
	Nodes []NodeTriple
}

var _ FixedPayload = &FindNodeRespPayload{}

func (fnresp *FindNodeRespPayload) MarshalBinary() ([]byte, error) {
	if len(fnresp.Nodes) > math.MaxUint8 {
		return nil, errors.New("node count exceeded")
	}
	data := make([]byte, 1+len(fnresp.Nodes)*NodeTripleSize)
	b := data

	b[0] = uint8(len(fnresp.Nodes))
	b = b[1:]

	for i, n := range fnresp.Nodes {
		if len(n.NodeID) != NodeIDSize {
			return nil, fmt.Errorf("node[%d] ID length invalid", i)
		}
		copy(b, n.NodeID)
		b = b[NodeIDSize:]

		binary.BigEndian.PutUint16(b, n.NodePort)
		b = b[2:]

		ip := n.NodeIP.To16()
		if ip == nil {
			return nil, fmt.Errorf("node[%d] IP invalid", i)
		}
		copy(b, ip)
		b = b[net.IPv6len:]
	}

	return data, nil
}

func (fnresp *FindNodeRespPayload) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < FindNodeRespPayloadMinSize {
		return 0, errors.New("payload truncated")
	}

	count := int(data[0])
	data = data[1:]

	if len(data) < count*NodeTripleSize {
		return 0, errors.New("payload truncated")
	}

	for i := 0; i < count; i++ {
		var n NodeTriple

		n.NodeID = make([]byte, NodeIDSize)
		copy(n.NodeID, data)
		data = data[NodeIDSize:]

		n.NodeIP = make([]byte, net.IPv6len)
		copy(n.NodeIP, data)
		data = data[net.IPv6len:]

		n.NodePort = binary.BigEndian.Uint16(data)
		data = data[2:]

		fnresp.Nodes = append(fnresp.Nodes, n)
	}

	return 1 + count*NodeTripleSize, nil
}

type FindValuePayload struct {
	Key []byte
}

var _ FixedPayload = &FindValuePayload{}

func (fval *FindValuePayload) MarshalBinary() ([]byte, error) {
	data := make([]byte, FindValuePayloadSize)
	b := data

	if len(fval.Key) != KeySize {
		return nil, errors.New("key invalid")
	}
	copy(b, fval.Key)
	b = b[KeySize:]

	return data, nil
}

func (fval *FindValuePayload) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < FindValuePayloadSize {
		return 0, errors.New("payload truncated")
	}

	fval.Key = make([]byte, KeySize)
	copy(fval.Key, data)
	data = data[KeySize:]

	return FindValuePayloadSize, nil
}

type ErrorPayload struct {
	ErrorMsg []byte
}

var _ FixedPayload = &ErrorPayload{}

func (er *ErrorPayload) MarshalBinary() ([]byte, error) {
	if len(er.ErrorMsg) == 0 {
		return nil, errors.New("error message too short")
	}
	if len(er.ErrorMsg) > math.MaxUint8 {
		return nil, errors.New("error message too long")
	}
	data := make([]byte, 1+len(er.ErrorMsg))
	b := data

	b[0] = uint8(len(er.ErrorMsg))
	b = b[1:]

	copy(b, er.ErrorMsg)
	b = b[len(er.ErrorMsg):]

	return data, nil
}

func (er *ErrorPayload) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < ErrorPayloadMinSize {
		return 0, errors.New("payload truncated")
	}

	length := int(data[0])
	data = data[1:]

	if len(data) < length {
		return 0, errors.New("error message truncated")
	}

	er.ErrorMsg = make([]byte, length)
	copy(er.ErrorMsg, data)
	data = data[length:]

	return 1 + length, nil
}
