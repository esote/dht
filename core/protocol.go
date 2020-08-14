package core

import (
	"errors"
	"io"
	"strings"

	"github.com/esote/dht/util"
)

// Different message types according to the message header TYPE field.
const (
	TypePing uint8 = iota
	TypeStore
	TypeFindNode
	TypeFindNodeResp
	TypeFindValue
	TypeFindValueResp

	TypeError = ^uint8(0)
)

// Magic is the unique identifier for messages conforming to PROTOCOL.
var Magic = [5]byte{0x8F, 0x4D, 'K', 'A', 'D'}

// Message contains a header and payload.
type Message struct {
	Hdr     *Header
	Payload Payload
}

// NewMessage decodes a new message from r.
func NewMessage(r io.Reader) (*Message, error) {
	var (
		msg Message
		err error
	)
	if msg.Hdr, err = NewHeader(r); err != nil {
		return nil, err
	}
	switch msg.Hdr.Type {
	case TypePing:
		msg.Payload, err = NewPing(r)
	case TypeStore:
		msg.Payload, err = NewStore(r)
	case TypeFindNode:
		msg.Payload, err = NewFindNode(r)
	case TypeFindNodeResp:
		msg.Payload, err = NewFindNodeResp(r)
	case TypeFindValue:
		msg.Payload, err = NewFindValue(r)
	case TypeFindValueResp:
		msg.Payload, err = NewFindValueResp(r)
	case TypeError:
		msg.Payload, err = NewError(r)
	default:
		return nil, errors.New("message type unknown")
	}
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

// Encode a message to w.
func (msg *Message) Encode(w io.Writer) error {
	if err := msg.Hdr.Encode(w); err != nil {
		return err
	}
	return msg.Payload.Encode(w)
}

// Header contains various identifying and meta information about a message.
type Header struct {
	Magic          [5]byte
	IdentityLength uint8
	Identity       []byte
	Type           uint8
	RPCID          ID
	Node           *Node
}

// NewHeader decodes a new header from r.
func NewHeader(r io.Reader) (*Header, error) {
	var (
		hdr Header
		err error
	)
	if _, err = r.Read(hdr.Magic[:]); err != nil {
		return nil, err
	}
	if hdr.Magic != Magic {
		return nil, errors.New("header magic incorrect")
	}
	if err = util.ReadNetwork(r, &hdr.IdentityLength); err != nil {
		return nil, err
	}
	hdr.Identity = make([]byte, hdr.IdentityLength)
	if _, err = r.Read(hdr.Identity); err != nil {
		return nil, err
	}
	if err = util.ReadNetwork(r, &hdr.Type); err != nil {
		return nil, err
	}
	if _, err = r.Read(hdr.RPCID[:]); err != nil {
		return nil, err
	}
	if hdr.Node, err = NewNode(r); err != nil {
		return nil, err
	}
	return &hdr, nil
}

// Encode a header to w.
func (hdr *Header) Encode(w io.Writer) (err error) {
	if _, err = w.Write(hdr.Magic[:]); err != nil {
		return
	}
	if err = util.WriteNetwork(w, hdr.IdentityLength); err != nil {
		return
	}
	if _, err = w.Write(hdr.Identity); err != nil {
		return
	}
	if bw, ok := w.(io.ByteWriter); ok {
		err = bw.WriteByte(hdr.Type)
	} else {
		_, err = w.Write([]byte{hdr.Type})
	}
	if err != nil {
		return
	}
	if _, err = w.Write(hdr.RPCID[:]); err != nil {
		return
	}
	return hdr.Node.Encode(w)
}

// Payload contains message-type-specific data.
type Payload interface {
	// Encode the payload to w.
	Encode(w io.Writer) error

	// Type gives the specific payload type, as defined in the message
	// header TYPE field.
	Type() uint8
}

// Ping corresponds to the PING message payload format.
type Ping struct{}

var _ Payload = &Ping{}

// NewPing decodes a PING payload from r.
func NewPing(r io.Reader) (*Ping, error) {
	return &Ping{}, nil
}

// Encode a PING payload to w.
func (ping *Ping) Encode(w io.Writer) error {
	return nil
}

// Type gives the PING message header TYPE value.
func (ping *Ping) Type() uint8 { return TypePing }

// Store corresponds to the STORE message payload format.
type Store struct {
	Key    ID
	Length uint64
	Value  io.Reader
}

var _ Payload = &Store{}

// NewStore decodes a STORE payload from r.
func NewStore(r io.Reader) (*Store, error) {
	var (
		store Store
		err   error
	)
	if _, err = r.Read(store.Key[:]); err != nil {
		return nil, err
	}
	if err = util.ReadNetwork(r, &store.Length); err != nil {
		return nil, err
	}
	if store.Length == 0 {
		return nil, errors.New("store length is zero")
	}
	store.Value = util.NewLimitedReader(r, store.Length)
	return &store, nil
}

// Encode a STORE payload to w.
func (store *Store) Encode(w io.Writer) (err error) {
	if _, err = w.Write(store.Key[:]); err != nil {
		return
	}
	if err = util.WriteNetwork(w, store.Length); err != nil {
		return
	}
	_, err = util.CopyN(w, store.Value, store.Length)
	return
}

// Type gives the STORE message header TYPE value.
func (store *Store) Type() uint8 { return TypeStore }

// FindNode corresponds to the FIND_NODE message payload format.
type FindNode struct {
	Count  uint8
	Target ID
}

var _ Payload = &FindNode{}

// NewFindNode decodes a FIND_NODE payload from r.
func NewFindNode(r io.Reader) (*FindNode, error) {
	var (
		fnode FindNode
		err   error
	)
	if err = util.ReadNetwork(r, &fnode.Count); err != nil {
		return nil, err
	}
	if _, err = r.Read(fnode.Target[:]); err != nil {
		return nil, err
	}
	return &fnode, nil
}

// Encode a FIND_NODE payload to w.
func (fnode *FindNode) Encode(w io.Writer) (err error) {
	if err = util.WriteNetwork(w, fnode.Count); err != nil {
		return
	}
	_, err = w.Write(fnode.Target[:])
	return
}

// Type gives the FIND_NODE message header TYPE value.
func (fnode *FindNode) Type() uint8 { return TypeFindNode }

// FindNodeResp corresponds to the FIND_NODE_RESP message payload format.
type FindNodeResp struct {
	Nodes []*Node
}

var _ Payload = &FindNodeResp{}

// NewFindNodeResp decodes a FIND_NODE_RESP payload from r.
func NewFindNodeResp(r io.Reader) (*FindNodeResp, error) {
	var (
		fnresp FindNodeResp
		count  uint8
	)
	if err := util.ReadNetwork(r, &count); err != nil {
		return nil, err
	}
	for i := uint8(0); i < count; i++ {
		n, err := NewNode(r)
		if err != nil {
			return nil, err
		}
		fnresp.Nodes = append(fnresp.Nodes, n)
	}
	return &fnresp, nil
}

// Encode a FIND_NODE_RESP payload to w.
func (fnresp *FindNodeResp) Encode(w io.Writer) (err error) {
	count := uint8(len(fnresp.Nodes))
	if err = util.WriteNetwork(w, count); err != nil {
		return
	}
	for _, n := range fnresp.Nodes {
		if err = n.Encode(w); err != nil {
			return
		}
	}
	return
}

// Type gives the FIND_NODE_RESP message header TYPE value.
func (fnresp *FindNodeResp) Type() uint8 { return TypeFindNodeResp }

// FindValue corresponds to the FIND_VALUE message payload format.
type FindValue struct {
	Key    ID
	Offset uint64
	Length uint64
}

var _ Payload = &FindValue{}

// NewFindValue decodes a FIND_VALUE payload from r.
func NewFindValue(r io.Reader) (*FindValue, error) {
	var (
		fval FindValue
		err  error
	)
	if _, err = r.Read(fval.Key[:]); err != nil {
		return nil, err
	}
	if err = util.ReadNetwork(r, &fval.Offset); err != nil {
		return nil, err
	}
	if err = util.ReadNetwork(r, &fval.Length); err != nil {
		return nil, err
	}
	return &fval, nil
}

// Encode a FIND_VALUE payload to w.
func (fval *FindValue) Encode(w io.Writer) (err error) {
	if _, err = w.Write(fval.Key[:]); err != nil {
		return
	}
	if err = util.WriteNetwork(w, fval.Offset); err != nil {
		return
	}
	return util.WriteNetwork(w, fval.Length)
}

// Type gives the FIND_VALUE message header TYPE value.
func (fval *FindValue) Type() uint8 { return TypeFindValue }

// FindValueResp corresponds to the FIND_VALUE_RESP message payload format.
type FindValueResp struct {
	Length uint64
	Value  io.Reader
}

var _ Payload = &FindValueResp{}

// NewFindValueResp decodes a FIND_VALUE_RESP payload from r.
func NewFindValueResp(r io.Reader) (*FindValueResp, error) {
	var fvresp FindValueResp
	if err := util.ReadNetwork(r, &fvresp.Length); err != nil {
		return nil, err
	}
	fvresp.Value = util.NewLimitedReader(r, fvresp.Length)
	return &fvresp, nil
}

// Encode a FIND_VALUE_RESP payload to w.
func (fvresp *FindValueResp) Encode(w io.Writer) (err error) {
	if err = util.WriteNetwork(w, fvresp.Length); err != nil {
		return
	}
	_, err = util.CopyN(w, fvresp.Value, fvresp.Length)
	return
}

// Type gives the FIND_VALUE_RESP message header TYPE value.
func (fvresp *FindValueResp) Type() uint8 { return TypeFindValueResp }

// Error corresponds to the ERROR message payload format.
type Error struct {
	Length uint64
	Value  io.Reader
}

var _ Payload = &Error{}

// NewErrorStr creates an Error payload from a string.
func NewErrorStr(s string) *Error {
	return &Error{
		Length: uint64(len(s)),
		Value:  strings.NewReader(s),
	}
}

// NewError decodes an ERROR payload from r.
func NewError(r io.Reader) (*Error, error) {
	var er Error
	if err := util.ReadNetwork(r, &er.Length); err != nil {
		return nil, err
	}
	er.Value = util.NewLimitedReader(r, er.Length)
	return &er, nil
}

// Encode an ERROR payload to w.
func (er *Error) Encode(w io.Writer) (err error) {
	if err = util.WriteNetwork(w, er.Length); err != nil {
		return
	}
	_, err = util.CopyN(w, er.Value, er.Length)
	return
}

// Type gives the ERROR message header TYPE value.
func (er *Error) Type() uint8 { return TypeError }
