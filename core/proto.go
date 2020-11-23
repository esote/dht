package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"

	"github.com/esote/dht/util"
	"golang.org/x/crypto/sha3"
)

const (
	Version = 0

	PreBodySize = 1 + 1

	FixedMessageSize    = 16384 // 2^14
	FixedCiphertextSize = 16246

	StreamCiphertextBlockSize = 65536

	RPCIDSize    = 20
	NodeIDSize   = ed25519.PublicKeySize
	DynXSize     = 64 // SHA3-512 output size, verified in init
	HdrNonceSize = 16

	HeaderSize = 1 + NodeIDSize + DynXSize + net.IPv6len + 2 + RPCIDSize +
		8 + HdrNonceSize

	KeySize        = sha512.Size / 2 // TODO: use full key, just use half when comparing
	NodeTripleSize = NodeIDSize + net.IPv6len + 2
	SigSize        = ed25519.SignatureSize

	StorePayloadSize           = KeySize + 8
	FindNodePayloadSize        = 1 + NodeIDSize
	FindNodeRespPayloadMinSize = 1
	FindValuePayloadSize       = KeySize + 8
	ErrorPayloadMinSize        = 1 + 1
)

func init() {
	if DynXSize != sha3.New512().Size() {
		panic("DynXSize incorrect")
	}

	// Key and node ID size must be equal to ensure XOR metric works.
	if KeySize != NodeIDSize {
		panic("KeySize must equal NodeIDSize")
	}
}

var SupportedVersions = map[uint8]bool{
	Version: true,
}

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
	BodyKind uint8
	Hdr      *Header
	Payload  MessagePayload
}

type Header struct {
	MsgType  uint8
	NodeID   []byte
	PuzDynX  []byte
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

	if len(hdr.NodeID) != NodeIDSize {
		return nil, errors.New("node ID invalid")
	}
	copy(b, hdr.NodeID)
	b = b[NodeIDSize:]

	if len(hdr.PuzDynX) != DynXSize {
		return nil, errors.New("dynamic x invalid")
	}
	copy(b, hdr.PuzDynX)
	b = b[DynXSize:]

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

	// Header nonce is not kept in type.
	if _, err := rand.Read(b[:HdrNonceSize]); err != nil {
		return nil, err
	}
	b = b[HdrNonceSize:]

	return data, nil
}

func (hdr *Header) UnmarshalBinary(data []byte) error {
	if len(data) < HeaderSize {
		return errors.New("truncated header")
	}

	hdr.MsgType = data[0]
	data = data[1:]

	hdr.NodeID = make([]byte, NodeIDSize)
	copy(hdr.NodeID, data)
	data = data[NodeIDSize:]

	hdr.PuzDynX = make([]byte, DynXSize)
	copy(hdr.PuzDynX, data)
	data = data[DynXSize:]

	hdr.NodeIP = make([]byte, net.IPv6len)
	copy(hdr.NodeIP, data)
	data = data[net.IPv6len:]

	hdr.NodePort = binary.BigEndian.Uint16(data)
	data = data[2:]

	hdr.RPCID = make([]byte, RPCIDSize)
	copy(hdr.RPCID, data)
	data = data[RPCIDSize:]

	hdr.Time = binary.BigEndian.Uint64(data)
	data = data[8:]

	// Header nonce is not kept in type.
	data = data[HdrNonceSize:]

	return nil
}

type MessagePayload interface {
	BodyKind() uint8
	MsgType() uint8
}

type FixedPayload interface {
	MessagePayload
	MarshalBinary() (data []byte, err error)
	UnmarshalBinaryN(data []byte) (n int, err error)
}

type StreamPayload interface {
	MessagePayload
	MarshalStream(w io.Writer) (err error)
	UnmarshalStream(r io.Reader) (err error)
}

type PingPayload struct {
}

var _ FixedPayload = &PingPayload{}

func (ping *PingPayload) MarshalBinary() ([]byte, error) {
	return []byte{}, nil
}

func (ping *PingPayload) UnmarshalBinaryN(data []byte) (int, error) {
	return 0, nil
}

func (ping *PingPayload) BodyKind() uint8 { return KindFixed }
func (ping *PingPayload) MsgType() uint8  { return TypePing }

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

func (store *StorePayload) UnmarshalBinaryN(data []byte) (int, error) {
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

func (store *StorePayload) BodyKind() uint8 { return KindFixed }
func (store *StorePayload) MsgType() uint8  { return TypeStore }

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

func (data *DataPayload) BodyKind() uint8 { return KindStream }
func (data *DataPayload) MsgType() uint8  { return TypeData }

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

func (fnode *FindNodePayload) UnmarshalBinaryN(data []byte) (int, error) {
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

func (fnode *FindNodePayload) BodyKind() uint8 { return KindFixed }
func (fnode *FindNodePayload) MsgType() uint8  { return TypeFindNode }

type NodeTriple struct {
	ID   []byte
	IP   net.IP
	Port uint16
}

func (n *NodeTriple) MarshalSlice(data []byte) error {
	if len(n.ID) != NodeIDSize {
		return errors.New("ID length invalid")
	}
	copy(data, n.ID)
	data = data[NodeIDSize:]

	ip := n.IP.To16()
	if ip == nil {
		return errors.New("IP invalid")
	}
	copy(data, ip)
	data = data[net.IPv6len:]

	binary.BigEndian.PutUint16(data, n.Port)
	data = data[2:]

	return nil
}

func (n *NodeTriple) UnmarshalSlice(data []byte) error {
	if len(data) < NodeTripleSize {
		return errors.New("node triple truncated")
	}

	n.ID = make([]byte, NodeIDSize)
	copy(n.ID, data)
	data = data[NodeIDSize:]

	n.IP = make([]byte, net.IPv6len)
	copy(n.IP, data)
	data = data[net.IPv6len:]

	n.Port = binary.BigEndian.Uint16(data)
	data = data[2:]
	return nil
}

type FindNodeRespPayload struct {
	Nodes []*NodeTriple
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
		if n == nil {
			return nil, fmt.Errorf("node[%d] is nil", i)
		}
		if err := n.MarshalSlice(b); err != nil {
			return nil, fmt.Errorf("node[%d] %s", i, err)
		}
		b = b[NodeTripleSize:]
	}

	return data, nil
}

func (fnresp *FindNodeRespPayload) UnmarshalBinaryN(data []byte) (int, error) {
	if len(data) < FindNodeRespPayloadMinSize {
		return 0, errors.New("payload truncated")
	}

	count := int(data[0])
	data = data[1:]

	if len(data) < count*NodeTripleSize {
		return 0, errors.New("payload truncated")
	}

	fnresp.Nodes = make([]*NodeTriple, count)
	for i := range fnresp.Nodes {
		fnresp.Nodes[i] = new(NodeTriple)
		if err := fnresp.Nodes[i].UnmarshalSlice(data); err != nil {
			return 0, fmt.Errorf("node[%d] %s", i, err)
		}
		data = data[NodeTripleSize:]
	}

	return 1 + count*NodeTripleSize, nil
}

func (fnresp *FindNodeRespPayload) BodyKind() uint8 { return KindFixed }
func (fnresp *FindNodeRespPayload) MsgType() uint8  { return TypeFindNodeResp }

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

func (fval *FindValuePayload) UnmarshalBinaryN(data []byte) (int, error) {
	if len(data) < FindValuePayloadSize {
		return 0, errors.New("payload truncated")
	}

	fval.Key = make([]byte, KeySize)
	copy(fval.Key, data)
	data = data[KeySize:]

	return FindValuePayloadSize, nil
}

func (fval *FindValuePayload) BodyKind() uint8 { return KindFixed }
func (fval *FindValuePayload) MsgType() uint8  { return TypeFindValue }

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

func (er *ErrorPayload) UnmarshalBinaryN(data []byte) (int, error) {
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

func (er *ErrorPayload) BodyKind() uint8 { return KindFixed }
func (er *ErrorPayload) MsgType() uint8  { return TypeError }
