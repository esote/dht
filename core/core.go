// Package core provides structures as defined in PROTOCOL and the Kademlia
// paper.
package core

import (
	"crypto/rand"
	"errors"
	"io"
	"math/bits"
	"net"

	"github.com/esote/dht/util"
)

// IDLen is the length of an ID.
const IDLen = 20

// ID is a unique identifier for a node or key. Pass by reference to avoid
// copying.
type ID [IDLen]byte

// NewID generates a cryptographically random ID.
func NewID() (id ID, err error) {
	_, err = rand.Read(id[:])
	return
}

// LCP gives the longest common prefix of two IDs according to the Kademlia XOR
// metric. If the IDs are invalid LCP returns -1. LCP can be understood as the
// count of leading zeros in (x XOR y).
func (x *ID) LCP(y *ID) int {
	if x == nil || y == nil {
		return -1
	}
	for i := 0; i < IDLen; i++ {
		if b := x[i] ^ y[i]; b != 0 {
			return i*8 + bits.LeadingZeros8(b)
		}
	}
	return IDLen*8 - 1
}

// Node represents some server on the network. IP must be of length net.IPv6len.
type Node struct {
	IP   net.IP
	Port uint16
	ID   ID
}

// NodeLength is the length, in bytes, of a node when encoded.
const NodeLength = net.IPv6len + 2 + IDLen

// NewNode decodes a new node from r.
func NewNode(r io.Reader) (*Node, error) {
	n := Node{
		IP: make([]byte, net.IPv6len),
	}
	var err error
	if _, err = r.Read(n.IP); err != nil {
		return nil, err
	}
	if err = util.ReadNetwork(r, &n.Port); err != nil {
		return nil, err
	}
	if _, err = r.Read(n.ID[:]); err != nil {
		return nil, err
	}
	return &n, nil
}

// Encode a node to w.
func (n *Node) Encode(w io.Writer) error {
	ip := n.IP.To16()
	if ip == nil {
		return errors.New("node IP invalid")
	}
	if _, err := w.Write(ip); err != nil {
		return err
	}
	if err := util.WriteNetwork(w, n.Port); err != nil {
		return err
	}
	_, err := w.Write(n.ID[:])
	return err
}
