package dht

import (
	"bytes"
	"errors"
	"io"
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
	"github.com/esote/dht/util"
	"github.com/esote/enc"
	"github.com/esote/util/pool"
)

const (
	k     = 32
	alpha = 3

	maxSessions  = 4096 // max active sessions
	maxListeners = 2    // listen to UDP and TCP at the same time

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
	Storer        Storer
	Logger        Logger
	IP            net.IP
	Port          uint16
	FixedTimeout  time.Duration // Timeout for fixed-length messages
	StreamTimeout time.Duration // Timeout for stream messages
}

type DHT struct {
	storer Storer
	rtable rtable.RTable
	logger Logger

	fixedTimeout  time.Duration
	streamTimeout time.Duration

	networkId []byte

	self *core.NodeTriple
	priv []byte
	x    []byte

	sman     *session.Manager
	handlers sync.WaitGroup

	listeners sync.WaitGroup
	tcp       *net.TCPListener
	udp       *net.UDPConn
	done      chan struct{}

	finders map[*find.Finder]bool
	findmu  sync.Mutex
	findwg  sync.WaitGroup

	updatePool *pool.Pool

	state int32 // atomic int used to close handlers
}

func NewDHT(config *DHTConfig) (*DHT, error) {
	if config == nil {
		return nil, errors.New("dht: config is nil")
	}
	if len(config.NetworkID) != core.NetworkIDSize ||
		bytes.Equal(config.NetworkID, []byte{0, 0, 0, 0}) {
		return nil, errors.New("dht: network ID missing or invalid")
	}
	logger := config.Logger
	if logger == nil {
		logger = NewConsoleLogger(LogInfo)
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
		logger.Log(LogInfo, "creating new keypair")
		publ, priv, x, err = createKeypair(config.Dir, config.Password)
		logger.Log(LogInfo, "keypair created")
	} else if err == nil {
		logger.Log(LogInfo, "loaded existing config")
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
	// After this, when returning in error the DHT should be closed.
	dht := &DHT{
		storer:        config.Storer,
		logger:        logger,
		fixedTimeout:  config.FixedTimeout,
		streamTimeout: config.StreamTimeout,
		networkId:     config.NetworkID,
		self: &core.NodeTriple{
			ID:   publ,
			IP:   config.IP,
			Port: config.Port,
		},
		priv:       priv,
		x:          x,
		done:       make(chan struct{}, maxListeners),
		finders:    make(map[*find.Finder]bool),
		updatePool: pool.New(maxUpdateWorkers, maxUpdateBacklog),
		state:      open,
	}
	dht.log(LogInfo, "self", nodeToString(dht.self))
	dht.rtable, err = rtable.NewRTable(publ, k, config.Dir)
	if err != nil {
		_ = dht.Close()
		return nil, err
	}
	dht.sman = session.NewManager(maxSessions, dht.handlerFunc)
	// TODO: OpenBSD requires opening separate tcp6 & udp6 listeners
	// TODO: OpenBSD doesn't support IPv4 mapped IPv6 addresses, always
	// convert to unmapped address where possible
	dht.tcp, err = net.ListenTCP("tcp", &net.TCPAddr{
		Port: int(config.Port),
	})
	if err != nil {
		_ = dht.Close()
		return nil, err
	}
	dht.listeners.Add(1)
	go dht.listenTCP()
	dht.udp, err = net.ListenUDP("udp", &net.UDPAddr{
		Port: int(config.Port),
	})
	if err != nil {
		_ = dht.Close()
		return nil, err
	}
	dht.listeners.Add(1)
	go dht.listenUDP()
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

// Rereader returns a new reader for the same source, allowing its stream to be
// "reread".
type Rereader interface {
	Next() (io.ReadCloser, error)
}

/*
	XXX: use multiwriter with buffered pipe, rather than Rereader
*/
func (dht *DHT) Store(key []byte, length uint64, value Rereader) error {
	if len(key) != core.KeySize {
		return errors.New("invalid key")
	}
	id := key[:core.NodeIDSize]
	cfg := &find.Config{
		Start:            []*core.NodeTriple{dht.self},
		Target:           id,
		Workers:          maxFindWorkers,
		MaxBacklogSize:   maxFindBacklogSize,
		MaxReturn:        maxFindReturn,
		MaxUniqueHistory: maxFindUniqueHistory,
		Query: func(target *core.NodeTriple) []*core.NodeTriple {
			return dht.findNode(id, target)
		},
	}

	f, err := find.Find(cfg)
	if err != nil {
		return err
	}
	dht.addFinder(f)

	closest := <-f.Done
	dht.removeFinder(f)

	if len(closest) == 0 {
		return errors.New("no nodes found")
	}
	dht.logf(LogDebug, "storing in %d nodes", len(closest))
	// Ask all nodes closest to key to store the value
	for _, n := range closest {
		v, err := value.Next()
		if err != nil {
			return err
		}
		// TODO: check close value
		defer v.Close() // TODO: close earlier
		dht.log(LogDebug, "storing in", nodeToString(n))
		if bytes.Equal(n.ID, dht.self.ID) {
			if err = dht.storer.Store(key, length, v); err != nil {
				dht.log(LogErr, err)
				// Continue execution
			}
		} else {
			if !dht.askStore(n, key, length, v) {
				dht.log(LogWarning, "unable to store in",
					nodeToString(n))
			}
		}
	}
	return nil
}

func (dht *DHT) Load(key []byte) (value io.ReadCloser, length uint64, err error) {
	if len(key) != core.KeySize {
		return nil, 0, errors.New("invalid key")
	}
	var found int32 = open
	var data *core.DataPayload
	var c io.Closer
	id := key[:core.NodeIDSize]
	cfg := &find.Config{
		Start:            []*core.NodeTriple{dht.self},
		Target:           id,
		Workers:          maxFindWorkers,
		MaxBacklogSize:   maxFindBacklogSize,
		MaxReturn:        maxFindReturn,
		MaxUniqueHistory: maxFindUniqueHistory,
		Query: func(target *core.NodeTriple) []*core.NodeTriple {
			if atomic.LoadInt32(&found) == closed {
				return nil
			}
			closest, data2, c2 := dht.findValue(key, target)
			if data2 != nil {
				if !atomic.CompareAndSwapInt32(&found, open, closed) {
					return nil
				}
				data, c = data2, c2
				return []*core.NodeTriple{{ID: id}}
			}
			return closest
		},
	}

	f, err := find.Find(cfg)
	if err != nil {
		return nil, 0, err
	}
	dht.addFinder(f)

	<-f.Done
	dht.removeFinder(f)

	if data == nil {
		return nil, 0, errors.New("value not found")
	}
	return util.JoinReadCloser(data.Value, c), data.Length, nil
}

func (dht *DHT) Bootstrap(id []byte, ip net.IP, port uint16) error {
	target := &core.NodeTriple{
		ID:   id,
		IP:   ip,
		Port: port,
	}
	rpcid, ch, done, hc, err := dht.newHandler()
	if err != nil {
		return err
	}
	// TODO: check close value
	defer hc.Close()

	fnode := &core.FindNodePayload{
		Count:  k,
		Target: dht.self.ID,
	}
	if err := dht.send(rpcid, fnode, target); err != nil {
		return err
	}

	msg, err := dht.recv(ch, done)
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
	// Stop accepting new connections.
	for i := 0; i < cap(dht.done); i++ {
		dht.done <- struct{}{}
	}
	dht.listeners.Wait()
	close(dht.done)
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
	if dht.tcp != nil {
		if err2 := dht.tcp.Close(); err == nil {
			err = err2
		}
	}
	if dht.udp != nil {
		if err2 := dht.udp.Close(); err == nil {
			err = err2
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

func (dht *DHT) listenUDP() {
	defer dht.listeners.Done()
	buf := make([]byte, core.FixedMessageSize)
	for {
		select {
		case <-dht.done:
			return
		default:
		}
		if err := dht.udp.SetDeadline(time.Now().Add(netAcceptTimeout)); err != nil {
			dht.log(LogErr, err)
			return
		}
		n, addr, err := dht.udp.ReadFrom(buf)
		if err != nil {
			if v, ok := err.(net.Error); !ok || !v.Timeout() {
				dht.log(LogWarning, err)
			}
			continue
		}
		var msg core.Message
		if err = msg.UnmarshalFixed(buf[:n], dht.priv); err != nil {
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

func (dht *DHT) listenTCP() {
	defer dht.listeners.Done()
	for {
		select {
		case <-dht.done:
			return
		default:
		}
		if err := dht.tcp.SetDeadline(time.Now().Add(netAcceptTimeout)); err != nil {
			dht.log(LogErr, err)
			return
		}
		conn, err := dht.tcp.Accept()
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
		if err = msg.UnmarshalStream(conn, dht.priv); err != nil {
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

func readKeypair(dir string, pass []byte) (publ, priv, x []byte, err error) {
	publ, err = ioutil.ReadFile(filepath.Join(dir, "publ"))
	if err != nil {
		return
	}
	encpriv, err := ioutil.ReadFile(filepath.Join(dir, "priv"))
	if err != nil {
		return
	}
	if err = enc.Decrypt(encpriv, pass, &priv); err != nil {
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
	encpriv, _, err := enc.Encrypt(pass, &priv)
	if err != nil {
		return
	}
	err = ioutil.WriteFile(filepath.Join(dir, "priv"), encpriv, 0600)
	if err != nil {
		return
	}
	err = ioutil.WriteFile(filepath.Join(dir, "x"), x, 0600)
	return
}
