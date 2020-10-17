package dht

import (
	"encoding/binary"
	"errors"
	"io/ioutil"
	"math/bits"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/esote/dht/core"
	"github.com/esote/dht/session"
)

type NodeID []byte

const NodeIDSize = core.NodeIDSize

func (x NodeID) LCP(y NodeID) int {
	for i := 0; i < NodeIDSize; i++ {
		if b := x[i] ^ y[i]; b != 0 {
			return i*8 + bits.LeadingZeros8(b)
		}
	}
	return NodeIDSize * 8
}

type KeyID []byte

const KeyIDSize = core.KeySize

// TODO: remove, use core.NodeTriple directly
type Node struct {
	ID   NodeID
	IP   net.IP
	Port uint16
}

const NodeSize = core.NodeTripleSize

func (n *Node) MarshalBinary() ([]byte, error) {
	data := make([]byte, NodeSize)
	b := data

	if len(n.ID) != core.NodeIDSize {
		return nil, errors.New("node ID length invalid")
	}
	copy(b, n.ID)
	b = b[core.NodeIDSize:]

	ip := n.IP.To16()
	if ip == nil {
		return nil, errors.New("nod IP invalid")
	}
	copy(b, ip)
	b = b[net.IPv6len:]

	binary.BigEndian.PutUint16(b, n.Port)
	b = b[2:]

	return data, nil
}

func (n *Node) UnmarshalBinary(data []byte) error {
	if len(data) < NodeSize {
		return errors.New("node truncated")
	}

	n.ID = make([]byte, core.NodeIDSize)
	copy(n.ID, data)
	data = data[core.NodeIDSize:]

	n.IP = make([]byte, net.IPv6len)
	copy(n.IP, data)
	data = data[net.IPv6len:]

	n.Port = binary.BigEndian.Uint16(data)
	data = data[2:]

	return nil
}

// TODO: unexport
const (
	K            = 20
	MaxSessions  = 4096 // max active sessions
	MaxListeners = 2    // listen to UDP and TCP at the same time
)

const (
	open int32 = iota
	closed
)

type DHT struct {
	storer Storer
	rtable RTable
	sman   *session.Manager

	timeout time.Duration

	publ []byte
	priv []byte
	x    []byte
	ip   net.IP
	port uint16

	handlers  sync.WaitGroup
	listeners sync.WaitGroup

	tcp *net.TCPListener
	udp *net.UDPConn

	done  chan struct{}
	state int32 // atomic int used to close handlers
}

type DHTConfig struct {
	Dir      string
	Password []byte
	Storer   Storer
	Boostrap []*Node
	IP       net.IP
	Port     uint16
	Timeout  time.Duration
}

// TODO: when returning an error it should try to close as much as possible
func NewDHT(config *DHTConfig) (*DHT, error) {
	if config == nil {
		return nil, errors.New("dht: config is nil")
	}
	config.Dir = filepath.Clean(config.Dir)
	info, err := os.Stat(config.Dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("dht: config.Dir is not a directory")
	}
	publ, priv, x, err := readKeypair(config.Dir, config.Password)
	if err != nil && os.IsNotExist(err) {
		publ, priv, x, err = createKeypair(config.Dir, config.Password)
	}
	if err != nil {
		return nil, err
	}
	if ip := config.IP.To4(); ip != nil {
		config.IP = ip
	} else if ip := config.IP.To16(); ip != nil {
		config.IP = ip
	} else {
		return nil, errors.New("dht: config.IP invalid")
	}
	dht := &DHT{
		storer:  config.Storer,
		timeout: config.Timeout,
		publ:    publ,
		priv:    priv,
		x:       x,
		ip:      config.IP,
		port:    config.Port,
		done:    make(chan struct{}, MaxSessions+MaxListeners),
		state:   open,
	}
	dht.rtable, err = NewRTable(publ, K, config.Dir)
	if err != nil {
		return nil, err
	}
	dht.sman = session.NewManager(MaxSessions, dht.handlerFunc)
	dht.tcp, err = net.ListenTCP("tcp", &net.TCPAddr{
		Port: int(config.Port),
	})
	if err != nil {
		return nil, err
	}
	dht.listeners.Add(1)
	go dht.listenTCP()
	dht.udp, err = net.ListenUDP("udp", &net.UDPAddr{
		Port: int(config.Port),
	})
	if err != nil {
		return nil, err
	}
	dht.listeners.Add(1)
	go dht.listenUDP()
	return dht, nil
}

func (dht *DHT) Close() error {
	if !atomic.CompareAndSwapInt32(&dht.state, open, closed) {
		return nil // TODO: err
	}
	for i := 0; i < cap(dht.done); i++ {
		dht.done <- struct{}{}
	}
	dht.handlers.Wait()
	dht.listeners.Wait()
	close(dht.done)
	var err error
	if err2 := dht.tcp.Close(); err == nil {
		err = err2
	}
	if err2 := dht.udp.Close(); err == nil {
		err = err2
	}
	if err2 := dht.sman.Close(); err == nil {
		err = err2
	}
	if err2 := dht.rtable.Close(); err == nil {
		err = err2
	}
	return err
}

/*
// TODO: return error, rather than bool
func (dht *DHT) ping(n *Node) bool {
	rpcid := make([]byte, core.RPCIDSize)
	if _, err := rand.Read(rpcid); err != nil {
		return false
	}
	req := core.Message{
		Version:  core.Version,
		BodyKind: core.KindFixed,
		Hdr: &core.Header{
			MsgType:  core.TypePing,
			NodeID:   dht.publ,
			PuzDynX:  dht.x,
			NodeIP:   dht.ip,
			NodePort: dht.port,
			RPCID:    rpcid,
			Time:     uint64(time.Now().Add(dht.timeout).Unix()),
		},
		Payload: &core.PingPayload{},
	}
	_ = req
	// TODO: send req to session manager, wait for response
	var resp core.Message
	_ = resp
	return true
}
*/

// TODO: log errors
func (dht *DHT) listenUDP() {
	defer dht.listeners.Done()
	buf := make([]byte, core.FixedMessageSize)
	for {
		// TODO: is this wanted?
		if err := dht.udp.SetDeadline(time.Now().Add(dht.timeout)); err != nil {
			return
		}
		select {
		case <-dht.done:
			return
		default:
		}
		n, addr, err := dht.udp.ReadFrom(buf)
		if err != nil {
			continue
		}
		var msg core.Message
		if err = msg.UnmarshalFixed(buf[:n], dht.priv); err != nil {
			continue
		}
		// XXX: verify remote addr matches msg addr
		_ = addr
		if err = dht.enqueue(&msg, nil); err != nil {
			continue
		}
	}
}

// TODO: log errors
func (dht *DHT) listenTCP() {
	defer dht.listeners.Done()
	for {
		// TODO: is this wanted?
		if err := dht.tcp.SetDeadline(time.Now().Add(dht.timeout)); err != nil {
			return
		}
		select {
		case <-dht.done:
			return
		default:
		}
		conn, err := dht.tcp.Accept()
		if err != nil {
			continue
		}
		if err = conn.SetDeadline(time.Now().Add(dht.timeout)); err != nil {
			continue
		}
		var msg core.Message
		if err = msg.UnmarshalStream(conn, dht.priv); err != nil {
			continue
		}
		// XXX: verify remote addr matches msg addr
		if err = dht.enqueue(&msg, conn); err != nil {
			continue
		}
		// XXX: close conn in dht handler or include io.Closer
		// when unmarshalling stream msg & leave for consumer to handler
		// (would still need to close on error)
	}
}

func readKeypair(dir string, pass []byte) (publ, priv, x []byte, err error) {
	publ, err = ioutil.ReadFile(filepath.Join(dir, "publ"))
	if err != nil {
		return
	}
	// XXX: decrypt
	priv, err = ioutil.ReadFile(filepath.Join(dir, "priv"))
	if err != nil {
		return
	}
	x, err = ioutil.ReadFile(filepath.Join(dir, "x"))
	return
}

func createKeypair(dir string, pass []byte) (publ, priv, x []byte, err error) {
	publ, priv, x, err = core.NewNodeID()
	if err != nil {
		return
	}
	err = ioutil.WriteFile(filepath.Join(dir, "publ"), publ, 0600)
	if err != nil {
		return
	}
	// XXX: encrypt
	err = ioutil.WriteFile(filepath.Join(dir, "priv"), priv, 0600)
	if err != nil {
		return
	}
	err = ioutil.WriteFile(filepath.Join(dir, "x"), x, 0600)
	return
}
