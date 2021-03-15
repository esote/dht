package dht

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/esote/dht/core"
	"github.com/esote/dht/find"
	"github.com/esote/dht/rtable"
	"github.com/esote/dht/session"
	"github.com/esote/dht/storer"
	"github.com/esote/enc"
	"github.com/esote/util/pool"
)

const (
	k     = 32
	alpha = 3

	c1 = 23
	c2 = 24

	maxSessions = 4096 // max active sessions

	maxFindWorkers       = alpha
	maxFindBacklogSize   = core.NodeIDSize * 8 * k
	maxFindReturn        = k
	maxFindUniqueHistory = maxFindBacklogSize

	maxUpdateWorkers = 5    // concurrent rtable updates
	maxUpdateBacklog = 1024 // queued rtable updates

	netAcceptTimeout = 250 * time.Millisecond
)

const (
	open int32 = iota
	closed
)

type DHTConfig struct {
	NetworkID     []byte
	Dir           string
	Password      []byte
	Storer        storer.Storer
	Logger        Logger
	IP            net.IP
	Port          uint16
	FixedTimeout  time.Duration // Timeout for fixed-length messages
	StreamTimeout time.Duration // Timeout for stream messages

	c1, c2 int
}

// Validate config and set default values.
func (config *DHTConfig) clean() error {
	if config == nil {
		return errors.New("dht: config is nil")
	}
	if len(config.NetworkID) != core.NetworkIDSize ||
		bytes.Equal(config.NetworkID, []byte{0, 0, 0, 0}) {
		return errors.New("dht: network ID missing or invalid")
	}
	if config.Logger == nil {
		config.Logger = NewConsoleLogger(LogInfo)
	}
	config.Dir = filepath.Clean(config.Dir)
	info, err := os.Stat(config.Dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("dht: config.Dir is not a directory")
	}
	if ip := config.IP.To4(); ip != nil {
		config.IP = ip
	} else if ip = config.IP.To16(); ip != nil {
		config.IP = ip
	} else {
		return errors.New("dht: config.IP invalid")
	}
	if config.c1 == 0 {
		config.c1 = c1
	}
	if config.c2 == 0 {
		config.c2 = c2
	}
	return nil
}

type DHT struct {
	storer storer.Storer
	rtable rtable.RTable
	logger Logger

	fixedTimeout  time.Duration
	streamTimeout time.Duration

	networkId []byte

	self *core.NodeTriple
	priv []byte
	x    []byte

	codec *core.MessageCodec

	sman     *session.Manager
	handlers sync.WaitGroup

	listeners sync.WaitGroup
	tcp       []*net.TCPListener
	udp       []*net.UDPConn
	done      chan struct{}

	finders map[*find.Finder]bool
	findmu  sync.Mutex
	findwg  sync.WaitGroup

	updatePool *pool.Pool

	state int32 // atomic int used to close handlers
}

func NewDHT(config *DHTConfig) (*DHT, error) {
	if err := config.clean(); err != nil {
		return nil, err
	}
	// After this, when returning in error the DHT should be closed.
	dht := &DHT{
		storer:        config.Storer,
		logger:        config.Logger,
		fixedTimeout:  config.FixedTimeout,
		streamTimeout: config.StreamTimeout,
		networkId:     config.NetworkID,
		self: &core.NodeTriple{
			IP:   config.IP,
			Port: config.Port,
		},
		codec:      core.NewMessageCodec(config.c1, config.c2),
		finders:    make(map[*find.Finder]bool),
		updatePool: pool.New(maxUpdateWorkers, maxUpdateBacklog),
		state:      open,
	}
	err := dht.loadKeypair(config.Dir, config.Password)
	switch {
	case err == nil:
		dht.log(LogInfo, "loaded existing config")
	case err != nil && os.IsNotExist(err):
		dht.log(LogInfo, "creating new keypair")
		if err = dht.createKeypair(config.Dir, config.Password); err != nil {
			_ = dht.Close()
			return nil, err
		}
		dht.log(LogInfo, "keypair created")
	default:
		_ = dht.Close()
		return nil, err
	}
	dht.log(LogInfo, "self", nodeToString(dht.self))
	dht.rtable, err = rtable.NewRTable(dht.self.ID, k, config.Dir)
	if err != nil {
		_ = dht.Close()
		return nil, err
	}
	dht.sman = session.NewManager(maxSessions, dht.handlerFunc)
	if err = dht.createListeners(int(config.Port)); err != nil {
		_ = dht.Close()
		return nil, err
	}
	// TODO: OpenBSD doesn't support IPv4 mapped IPv6 addresses, always
	// convert to unmapped address where possible
	listening := len(dht.tcp) + len(dht.udp)
	dht.done = make(chan struct{}, listening)
	dht.listeners.Add(listening)
	for i := range dht.tcp {
		go dht.listenTCP(dht.tcp[i])
	}
	for i := range dht.udp {
		go dht.listenUDP(dht.udp[i])
	}
	return dht, nil
}

func (dht *DHT) log(level LogLevel, a ...interface{}) {
	dht.logger.Log(level, a...)
}

func (dht *DHT) logf(level LogLevel, format string, a ...interface{}) {
	dht.logger.Logf(level, format, a...)
}

func (dht *DHT) addFinder(f *find.Finder) {
	dht.findwg.Add(1)
	dht.findmu.Lock()
	defer dht.findmu.Unlock()
	dht.finders[f] = true
}

func (dht *DHT) removeFinder(f *find.Finder) {
	defer dht.findwg.Done()
	dht.findmu.Lock()
	defer dht.findmu.Unlock()
	delete(dht.finders, f)
}

func (dht *DHT) Bootstrap(id []byte, ip net.IP, port uint16) (err error) {
	target := &core.NodeTriple{
		ID:   id,
		IP:   ip,
		Port: port,
	}
	s, err := dht.newSession()
	if err != nil {
		return err
	}
	defer func() {
		if err2 := s.Close(); err == nil {
			err = err2
		}
	}()

	fnode := &core.FindNodePayload{
		Count:  k,
		Target: dht.self.ID,
	}
	if err = s.send(fnode, target); err != nil {
		return err
	}
	msg, err := s.recv()
	if err != nil {
		return err
	}
	// Close immediately, no stream message expected.
	if err = msg.Close(); err != nil {
		return err
	}
	switch v := msg.Payload.(type) {
	case *core.FindNodeRespPayload:
		if len(v.Nodes) > 0 && bytes.Equal(v.Nodes[0].ID, dht.self.ID) {
			// Target already knew about self.
			v.Nodes = v.Nodes[1:]
		}
		if len(v.Nodes) > k {
			v.Nodes = v.Nodes[:k]
		}
		dht.update(target)
		for _, n := range v.Nodes {
			dht.update(n)
		}
		return nil
	case *core.ErrorPayload:
		return errors.New(string(v.Msg))
	default:
		return errors.New("received unexpected payload type")
	}
}

func (dht *DHT) Close() error {
	if !atomic.CompareAndSwapInt32(&dht.state, open, closed) {
		return errors.New("close on closed DHT")
	}
	// Stop accepting new connections. Don't close connections yet because
	// that closes value readers.
	for i := 0; i < cap(dht.done); i++ {
		dht.done <- struct{}{}
	}
	dht.listeners.Wait()
	if dht.done != nil {
		close(dht.done)
	}
	var err error

	// Halt running sessions.
	if dht.sman != nil {
		if err2 := dht.sman.Close(); err == nil {
			err = err2
		}
	}
	dht.handlers.Wait()

	// Halt running finders
	dht.findmu.Lock()
	for f := range dht.finders {
		if err2 := f.Close(); err == nil {
			err = err2
		}
	}
	dht.findmu.Unlock()
	dht.findwg.Wait()

	// Disconnect existing connections.
	for _, l := range dht.tcp {
		if l != nil {
			if err2 := l.Close(); err == nil {
				err = err2
			}
		}
	}
	for _, l := range dht.udp {
		if l != nil {
			if err2 := l.Close(); err == nil {
				err = err2
			}
		}
	}

	// Stop trying to update RTable.
	if dht.updatePool != nil {
		dht.updatePool.Close(false)
	}

	// Close rtable kbucket SQLite3 databases.
	if dht.rtable != nil {
		if err2 := dht.rtable.Close(); err == nil {
			err = err2
		}
	}
	return err
}

func (dht *DHT) listenUDP(udp *net.UDPConn) {
	defer dht.listeners.Done()
	buf := make([]byte, core.FixedMessageSize)
	for {
		select {
		case <-dht.done:
			return
		default:
		}
		if err := udp.SetDeadline(time.Now().Add(netAcceptTimeout)); err != nil {
			dht.log(LogErr, err)
			return
		}
		n, addr, err := udp.ReadFrom(buf)
		if err != nil {
			if v, ok := err.(net.Error); !ok || !v.Timeout() {
				dht.log(LogWarning, err)
			}
			continue
		}
		var msg core.Message
		if err = dht.codec.DecodeFixed(&msg, buf[:n], dht.priv); err != nil {
			dht.log(LogWarning, err)
			continue
		}
		if !bytes.Equal(msg.Hdr.NetworkID, dht.networkId) {
			// Drop message
			continue
		}
		// XXX: verify remote addr matches msg addr?
		_ = addr
		err = dht.sman.Enqueue(&session.MessageCloser{
			Message: &msg,
			Closer:  &nopCloser{},
		})
		if err != nil {
			dht.log(LogErr, err)
		}
	}
}

func (dht *DHT) listenTCP(tcp *net.TCPListener) {
	defer dht.listeners.Done()
	for {
		select {
		case <-dht.done:
			return
		default:
		}
		if err := tcp.SetDeadline(time.Now().Add(netAcceptTimeout)); err != nil {
			dht.log(LogErr, err)
			return
		}
		conn, err := tcp.Accept()
		if err != nil {
			if v, ok := err.(net.Error); !ok || !v.Timeout() {
				dht.log(LogWarning, err)
			}
			continue
		}
		if err = conn.SetDeadline(time.Now().Add(dht.streamTimeout)); err != nil {
			_ = conn.Close()
			dht.log(LogErr, err)
			continue
		}
		var msg core.Message
		if err = dht.codec.DecodeStream(&msg, conn, dht.priv); err != nil {
			_ = conn.Close()
			dht.log(LogWarning, err)
			continue
		}
		if !bytes.Equal(msg.Hdr.NetworkID, dht.networkId) {
			// Drop message
			continue
		}
		// XXX: verify remote addr matches msg addr?
		// TODO: ensure conn is always closed in handler eventually,
		// even if session expires or sman is closed
		err = dht.sman.Enqueue(&session.MessageCloser{
			Message: &msg,
			Closer:  conn,
		})
		if err != nil {
			_ = conn.Close()
			dht.log(LogErr, err)
		}
	}
}

func (dht *DHT) loadKeypair(dir string, pass []byte) (err error) {
	dht.self.ID, err = ioutil.ReadFile(filepath.Join(dir, "publ"))
	if err != nil {
		return
	}
	encpriv, err := ioutil.ReadFile(filepath.Join(dir, "priv"))
	if err != nil {
		return
	}
	if err = enc.Decrypt(encpriv, pass, &dht.priv); err != nil {
		return
	}
	dht.x, err = ioutil.ReadFile(filepath.Join(dir, "x"))
	return
}

func (dht *DHT) createKeypair(dir string, pass []byte) (err error) {
	dht.self.ID, dht.priv, dht.x, err = dht.codec.NewNodeID()
	if err != nil {
		return
	}
	err = ioutil.WriteFile(filepath.Join(dir, "publ"), dht.self.ID, 0600)
	if err != nil {
		return
	}
	encpriv, _, err := enc.Encrypt(pass, &dht.priv)
	if err != nil {
		return
	}
	err = ioutil.WriteFile(filepath.Join(dir, "priv"), encpriv, 0600)
	if err != nil {
		return
	}
	err = ioutil.WriteFile(filepath.Join(dir, "x"), dht.x, 0600)
	return
}
