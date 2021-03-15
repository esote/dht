package dht

import "net"

// Create TCP and UDP listeners, IPv4 and IPv6 traffic are routed to a common
// listener.
func (dht *DHT) createListeners(port int) (err error) {
	dht.tcp = make([]*net.TCPListener, 1)
	tcpaddr := &net.TCPAddr{
		Port: port,
	}
	dht.tcp[0], err = net.ListenTCP("tcp", tcpaddr)
	if err != nil {
		return
	}

	dht.udp = make([]*net.UDPConn, 1)
	udpaddr := &net.UDPAddr{
		Port: port,
	}
	dht.udp[0], err = net.ListenUDP("udp4", udpaddr)
	return
}
