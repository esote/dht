package dht

import "net"

// Create TCP and UDP listeners, IPv4 and IPv6 traffic are routed separately.
func (dht *DHT) createListeners(port int) (err error) {
	// tcp[0] = inet, tcp[1] = inet6
	dht.tcp = make([]*net.TCPListener, 2)
	tcpaddr := &net.TCPAddr{
		Port: port,
	}
	dht.tcp[0], err = net.ListenTCP("tcp4", tcpaddr)
	if err != nil {
		return
	}
	dht.tcp[1], err = net.ListenTCP("tcp6", tcpaddr)
	if err != nil {
		return
	}

	// udp[0] = inet, tcp[1] = inet6
	dht.udp = make([]*net.UDPConn, 2)
	udpaddr := &net.UDPAddr{
		Port: port,
	}
	dht.udp[0], err = net.ListenUDP("udp4", udpaddr)
	if err != nil {
		return
	}
	dht.udp[1], err = net.ListenUDP("udp6", udpaddr)
	return
}
