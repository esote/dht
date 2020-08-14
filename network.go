package dht

import (
	"net"
)

// Network communicates with other nodes. Network is safe for concurrent use.
type Network interface {
	// Listener accepts connections from other nodes.
	// Listener.Addr().String() must return an IP address as the host.
	net.Listener

	// Dial a network address.
	Dial(address string) (net.Conn, error)
}

type tcpNet struct {
	net.Listener
	d *net.Dialer
}

var _ Network = &tcpNet{}

// DefaultNetworkPort is a randomly chosen port which Networks may choose to use
// as their default.
const DefaultNetworkPort = ":14530"

// NewTCPNetwork constructs a Network which uses TCP.
func NewTCPNetwork(port string) (Network, error) {
	l, err := net.Listen("tcp", port)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	return &tcpNet{
		Listener: l,
		d:        &d,
	}, nil
}

func (net *tcpNet) Dial(address string) (net.Conn, error) {
	return net.d.Dial("tcp", address)
}
