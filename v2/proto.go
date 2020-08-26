package dht

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/esote/dht/util"
)

const (
	Version = 0

	HeaderSize = 216

	DynXSize  = sha512.Size
	RPCIDSize = 20
	NonceSize = 8

	StoreSize           = 72
	DataMinSize         = 9
	FindNodeSize        = 33
	FindNodeRespMinSize = 1
	FindNodeRespMaxSize = 12751
	FindValueSize       = 80
	ErrorMinSize        = 2
	ErrorMaxSize        = 257

	UDPMaxSize = 12967

	NodeTripleSize = net.IPv6len + 2 + ed25519.PublicKeySize

	ProtoUDP = "udp"
	ProtoTCP = "tcp"
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

var SupportedVersions = map[uint8]bool{
	Version: true,
}

type Message struct {
	Hdr     *Header
	Payload Payload
}

func ReadUDPMessage(c net.PacketConn) (*Message, error) {
	buf := make([]byte, UDPMaxSize)
	n, addr, err := c.ReadFrom(buf)
	// XXX: ReadFrom docs: "Callers should always process the n > 0 bytes
	// returned before considering the error err" -- when should err be
	// checked?
	if err != nil {
		return nil, err
	}
	// XXX: check if addr.String() == hdr.NodeIP.String()? Probably not if
	// we want to allow nodes behind proxies or behind anonymous networks.
	_ = addr
	buf = buf[:n]

	var hdr Header
	if err = hdr.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	buf = buf[HeaderSize:]

	// Validate header.
	if _, ok := SupportedVersions[hdr.Version]; ok {
		return nil, fmt.Errorf("unsupported version %d", hdr.Version)
	}
	switch hdr.Type {
	case TypePing,
		TypeStore,
		TypeFindNode,
		TypeFindNodeResp,
		TypeFindValue,
		TypeError:
	default:
		return nil, fmt.Errorf("type unsupported %d", hdr.Type)
	}
	if !VerifyNodeID(hdr.NodeID, hdr.PuzDynX) {
		return nil, errors.New("message node ID generated incorrectly")
	}
	signed := buf[1+ed25519.SignatureSize:]
	if !ed25519.Verify(hdr.NodeID, signed, hdr.Sig) {
		return nil, errors.New("message signature invalid")
	}
	if ip := hdr.NodeIP.To16(); ip == nil {
		return nil, fmt.Errorf("message node IP %v invalid", hdr.NodeIP)
	} else {
		hdr.NodeIP = ip
	}
	if hdr.Time > uint64(math.MaxInt64) {
		return nil, errors.New("message time too large")
	}
	if time.Unix(int64(hdr.Time), 0).UTC().After(time.Now().UTC()) {
		return nil, errors.New("message expired")
	}
	var p UDPPayload
	switch hdr.Type {
	case TypePing:
		p = &PingPayload{}
	case TypeStore:
		p = &StorePayload{}
	case TypeFindNode:
		p = &FindNodePayload{}
	case TypeFindNodeResp:
		p = &FindNodeRespPayload{}
	case TypeFindValue:
		p = &FindValuePayload{}
	case TypeError:
		p = &ErrorPayload{}
	default:
		panic("invalid message type bypassed earlier check")
	}
	if err = p.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return &Message{
		Hdr:     &hdr,
		Payload: p,
	}, nil
}

func SendUDPMessage(c net.PacketConn, msg *Message) error {
	if msg.Payload.Protocol() != ProtoUDP {
		return errors.New("cannot send non-UDP message")
	}
	udp, ok := msg.Payload.(UDPPayload)
	if !ok {
		return errors.New("non-UDP payload using UDP protocol")
	}
	data := make([]byte, UDPMaxSize)
	hdr, err := msg.Hdr.MarshalBinary()
	if err != nil {
		return err
	}
	copy(data, hdr)
	p, err := udp.MarshalBinary()
	if err != nil {
		return err
	}
	copy(data[len(hdr):], p)

	data = data[:len(hdr)+len(p)]

	addr := &net.UDPAddr{
		IP:   msg.Hdr.NodeIP.To16(),
		Port: int(msg.Hdr.NodePort),
	}
	_, err = c.WriteTo(data, addr)
	return err
}

type Header struct {
	Version  uint8
	Sig      []byte
	Type     uint8
	NodeIP   net.IP
	NodePort uint16
	NodeID   ed25519.PublicKey
	PuzDynX  []byte
	RPCID    []byte
	Time     uint64
	Nonce    []byte
}

var _ encoding.BinaryMarshaler = &Header{}
var _ encoding.BinaryUnmarshaler = &Header{}

func (hdr *Header) MarshalBinary() (data []byte, err error) {
	data = make([]byte, HeaderSize)
	b := data

	b[0] = hdr.Version
	b = b[1:]

	copy(b, hdr.Sig[:ed25519.SignatureSize])
	b = b[ed25519.SignatureSize:]

	b[0] = hdr.Type
	b = b[1:]

	ip := hdr.NodeIP.To16()
	if ip == nil {
		return nil, fmt.Errorf("ip %v invalid", hdr.NodeIP)
	}
	copy(b, ip)
	b = b[net.IPv6len:]

	binary.BigEndian.PutUint16(b[:2], hdr.NodePort)
	b = b[2:]

	copy(b, hdr.NodeID[:ed25519.PublicKeySize])
	b = b[ed25519.PublicKeySize:]

	copy(b, hdr.PuzDynX[:DynXSize])
	b = b[DynXSize:]

	copy(b, hdr.RPCID[:RPCIDSize])
	b = b[RPCIDSize:]

	binary.BigEndian.PutUint64(b[:8], hdr.Time)
	b = b[8:]

	copy(b, hdr.Nonce[:NonceSize])
	b = b[NonceSize:]

	return
}

func (hdr *Header) UnmarshalBinary(data []byte) error {
	if len(data) < HeaderSize {
		return errors.New("message header truncated")
	}

	hdr.Version = data[0]
	data = data[1:]

	hdr.Sig = make([]byte, ed25519.SignatureSize)
	copy(hdr.Sig, data[:ed25519.SignatureSize])
	data = data[ed25519.SignatureSize:]

	hdr.Type = data[0]
	data = data[1:]

	hdr.NodeIP = make([]byte, net.IPv6len)
	copy(hdr.NodeIP, data[:net.IPv6len])
	data = data[net.IPv6len:]

	hdr.NodePort = binary.BigEndian.Uint16(data[:2])
	data = data[2:]

	hdr.NodeID = make([]byte, ed25519.PublicKeySize)
	copy(hdr.NodeID, data[:ed25519.PublicKeySize])
	data = data[ed25519.PublicKeySize:]

	hdr.PuzDynX = make([]byte, DynXSize)
	copy(hdr.PuzDynX, data[:DynXSize])
	data = data[DynXSize:]

	hdr.RPCID = make([]byte, RPCIDSize)
	copy(hdr.RPCID, data[:RPCIDSize])
	data = data[RPCIDSize:]

	hdr.Time = binary.BigEndian.Uint64(data[:8])
	data = data[8:]

	hdr.Nonce = make([]byte, NonceSize)
	copy(hdr.Nonce, data[:NonceSize])
	data = data[NonceSize:]

	return nil
}

type Payload interface {
	Protocol() string
}

type UDPPayload interface {
	Payload
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type TCPPayload interface {
	Payload
	MarshalStream(w io.Writer) error
	UnmarshalStream(r io.Reader) error
}

type PingPayload struct {
}

var _ UDPPayload = &PingPayload{}

func (ping *PingPayload) Protocol() string {
	return ProtoUDP
}

func (ping *PingPayload) MarshalBinary() (data []byte, err error) {
	return []byte{}, nil
}

func (ping *PingPayload) UnmarshalBinary(data []byte) error {
	return nil
}

type StorePayload struct {
	Key    []byte
	Length uint64
}

var _ UDPPayload = &StorePayload{}

func (store *StorePayload) Protocol() string {
	return ProtoUDP
}

func (store *StorePayload) MarshalBinary() (data []byte, err error) {
	data = make([]byte, sha512.Size+8)
	b := data

	copy(b[:sha512.Size], store.Key)
	b = b[sha512.Size:]

	binary.BigEndian.PutUint64(b[:8], store.Length)
	b = b[8:]

	return
}

func (store *StorePayload) UnmarshalBinary(data []byte) error {
	if len(data) < StoreSize {
		return errors.New("store message truncated")
	}

	store.Key = make([]byte, sha512.Size)
	copy(store.Key, data[:sha512.Size])
	data = data[sha512.Size:]

	store.Length = binary.BigEndian.Uint64(data[:8])
	data = data[8:]

	return nil
}

type DataPayload struct {
	Length uint64
	Value  io.Reader
}

var _ TCPPayload = &DataPayload{}

func (data *DataPayload) Protocol() string {
	return ProtoTCP
}

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
	Target ed25519.PublicKey
}

var _ UDPPayload = &FindNodePayload{}

func (fnode *FindNodePayload) Protocol() string {
	return ProtoUDP
}

func (fnode *FindNodePayload) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 1+ed25519.PublicKeySize)
	b := data

	b[0] = fnode.Count
	b = b[1:]

	copy(b[:ed25519.PublicKeySize], fnode.Target)
	b = b[ed25519.PublicKeySize:]

	return
}

func (fnode *FindNodePayload) UnmarshalBinary(data []byte) error {
	if len(data) < FindNodeSize {
		return errors.New("find node message truncated")
	}

	fnode.Count = data[0]
	data = data[1:]

	fnode.Target = make([]byte, ed25519.PublicKeySize)
	copy(fnode.Target, data[:ed25519.PublicKeySize])
	data = data[ed25519.PublicKeySize:]

	return nil
}

type NodeTriple struct {
	IP   net.IP
	Port uint16
	ID   ed25519.PublicKey
}

type FindNodeRespPayload struct {
	Count uint8
	Nodes []NodeTriple
}

var _ UDPPayload = &FindNodeRespPayload{}

func (fnresp *FindNodeRespPayload) Protocol() string {
	return ProtoUDP
}

func (fnresp *FindNodeRespPayload) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 1+fnresp.Count*NodeTripleSize)
	b := data

	b[0] = fnresp.Count
	b = b[1:]

	for i := uint8(0); i < fnresp.Count; i++ {
		ip := fnresp.Nodes[i].IP.To16()
		if ip == nil {
			return nil, fmt.Errorf("ip[%d] %v invalid", i,
				fnresp.Nodes[i].IP)
		}
		copy(b[:net.IPv6len], ip)
		b = b[net.IPv6len:]

		binary.BigEndian.PutUint16(b[:2], fnresp.Nodes[i].Port)
		b = b[2:]

		copy(b[:ed25519.PublicKeySize], fnresp.Nodes[i].ID)
		b = b[ed25519.PublicKeySize:]
	}

	return
}

func (fnresp *FindNodeRespPayload) UnmarshalBinary(data []byte) error {
	if len(data) < FindNodeRespMinSize {
		return errors.New("find node resp message truncated")
	}

	fnresp.Count = data[0]
	data = data[1:]

	if len(data) < int(fnresp.Count)*NodeTripleSize {
		return errors.New("find node resp message truncated")
	}

	for i := uint8(0); i < fnresp.Count; i++ {
		var n NodeTriple

		n.IP = make([]byte, net.IPv6len)
		copy(n.IP, data[:net.IPv6len])
		data = data[net.IPv6len:]

		n.Port = binary.BigEndian.Uint16(data[:2])
		data = data[2:]

		n.ID = make([]byte, ed25519.PublicKeySize)
		copy(n.ID, data[:ed25519.PublicKeySize])
		data = data[ed25519.PublicKeySize:]
	}

	return nil
}

type FindValuePayload struct {
	Key    []byte
	Offset uint64
	Length uint64
}

var _ UDPPayload = &FindValuePayload{}

func (fval *FindValuePayload) Protocol() string {
	return ProtoUDP
}

func (fval *FindValuePayload) MarshalBinary() (data []byte, err error) {
	data = make([]byte, sha512.Size+8+8)
	b := data

	copy(b[:sha512.Size], fval.Key)
	b = b[sha512.Size:]

	binary.BigEndian.PutUint64(b[:8], fval.Offset)
	b = b[8:]

	binary.BigEndian.PutUint64(b[:8], fval.Length)
	b = b[8:]

	return
}

func (fval *FindValuePayload) UnmarshalBinary(data []byte) error {
	if len(data) < FindValueSize {
		return errors.New("find value message truncated")
	}

	fval.Key = make([]byte, sha512.Size)
	copy(fval.Key, data[:sha512.Size])
	data = data[sha512.Size:]

	fval.Offset = binary.BigEndian.Uint64(data[:8])
	data = data[8:]

	fval.Length = binary.BigEndian.Uint64(data[:8])
	data = data[8:]

	return nil
}

type ErrorPayload struct {
	Length   uint16
	ErrorMsg []byte
}

var _ UDPPayload = &ErrorPayload{}

func (er *ErrorPayload) Protocol() string {
	return ProtoUDP
}

func (er *ErrorPayload) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 2+er.Length)
	b := data

	binary.BigEndian.PutUint16(b[:2], er.Length)
	b = b[2:]

	copy(b[:er.Length], er.ErrorMsg)
	b = b[er.Length:]

	return
}

func (er *ErrorPayload) UnmarshalBinary(data []byte) error {
	if len(data) < ErrorMinSize {
		return errors.New("error message truncated")
	}

	er.Length = binary.BigEndian.Uint16(data[:2])
	data = data[2:]

	if len(data) < int(er.Length) {
		return errors.New("error message truncated")
	}

	er.ErrorMsg = make([]byte, er.Length)
	copy(er.ErrorMsg, data[:er.Length])
	data = data[er.Length:]

	return nil
}
