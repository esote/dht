package dht

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/esote/dht/core"
	"github.com/esote/dht/rtable"
	"github.com/esote/dht/session"
	"github.com/esote/dht/util"
	"github.com/esote/enc"
)

const (
	k                = 20
	maxSessions      = 4096 // max active sessions
	maxListeners     = 2    // listen to UDP and TCP at the same time
	maxFindWorkers   = 3    // max concurrent find workers (alpha from paper)
	maxFindHeapSize  = 1000 // max node count in find heap backlog
	netAcceptTimeout = 100 * time.Millisecond
)

const (
	open int32 = iota
	closed
)

type DHT struct {
	storer Storer
	rtable rtable.RTable
	logger Logger

	fixedTimeout  time.Duration
	streamTimeout time.Duration

	self *core.NodeTriple
	priv []byte
	x    []byte

	sman     *session.Manager
	handlers sync.WaitGroup

	listeners sync.WaitGroup
	tcp       *net.TCPListener
	udp       *net.UDPConn
	done      chan struct{}

	finders map[*finder]bool
	findmu  sync.Mutex
	findwg  sync.WaitGroup

	state int32 // atomic int used to close handlers
}

type DHTConfig struct {
	Dir           string
	Password      []byte
	Storer        Storer
	Logger        Logger
	IP            net.IP
	Port          uint16
	FixedTimeout  time.Duration // Timeout for fixed-length messages
	StreamTimeout time.Duration // Timeout for stream messages
}

func NewDHT(config *DHTConfig) (*DHT, error) {
	if config == nil {
		return nil, errors.New("dht: config is nil")
	}
	logger := config.Logger
	if logger == nil {
		logger = &defaultLogger{}
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
	} else {
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
		self: &core.NodeTriple{
			ID:   publ,
			IP:   config.IP,
			Port: config.Port,
		},
		priv:    priv,
		x:       x,
		done:    make(chan struct{}, maxListeners),
		finders: make(map[*finder]bool),
		state:   open,
	}
	dht.logf(LogInfo, "self %s %s %d\n", hex.EncodeToString(dht.self.ID),
		dht.self.IP, dht.self.Port)
	dht.rtable, err = rtable.NewRTable(publ, k, config.Dir)
	if err != nil {
		_ = dht.Close()
		return nil, err
	}
	dht.sman = session.NewManager(maxSessions, dht.handlerFunc)
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

func (dht *DHT) addFinder(f *finder) {
	dht.findwg.Add(1)
	dht.findmu.Lock()
	defer dht.findmu.Unlock()
	dht.finders[f] = true
}

func (dht *DHT) removeFinder(f *finder) {
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

	XXX: limit size of map / when to halt querying b/c of too much
	memory usage
*/
func (dht *DHT) Store(key []byte, length uint64, value Rereader) error {
	if len(key) != core.KeySize {
		return errors.New("invalid key")
	}
	unique := make(map[string]bool)
	unique[string(dht.self.ID)] = true
	cfg := &findConfig{
		Start:   []*core.NodeTriple{dht.self},
		Target:  key,
		K:       k,
		Workers: maxFindWorkers,
		Max:     maxFindHeapSize,
		Query: func(target *core.NodeTriple) []*core.NodeTriple {
			closest, err := dht.queryStore(key, target, unique)
			if err != nil {
				dht.log(LogErr, err)
				return nil
			}
			return closest
		},
	}

	f, err := find(cfg)
	if err != nil {
		return err
	}
	dht.addFinder(f)

	closest := <-f.Done
	dht.removeFinder(f)

	if len(closest) == 0 {
		return errors.New("no nearby nodes found")
	}
	dht.logf(LogDebug, "storing in %d nodes\n", len(closest))
	// Ask all nodes closest to key to store the value
	for _, n := range closest {
		v, err := value.Next()
		if err != nil {
			return err
		}
		dht.logf(LogInfo, "storing %s %s %d\n",
			hex.EncodeToString(n.ID), n.IP, n.Port)
		if bytes.Equal(n.ID, dht.self.ID) {
			err = dht.storer.Store(key, length, v)
		} else {
			err = dht.askStore(n, key, length, v)
		}
		if err != nil {
			dht.log(LogErr, err)
			// Continue execution
		}
	}
	return nil
}

func (dht *DHT) queryStore(key []byte, target *core.NodeTriple, unique map[string]bool) ([]*core.NodeTriple, error) {
	var closest []*core.NodeTriple
	var err error
	if bytes.Equal(target.ID, dht.self.ID) {
		closest, err = dht.rtable.Closest(key, k)
		if err != nil {
			return nil, err
		}
		dht.logf(LogDebug, "got %d nodes from self\n", len(closest))
	} else {
		rpcid, ch, done, hc, err := dht.newHandler()
		if err != nil {
			return nil, err
		}
		defer hc.Close()

		fnode := &core.FindNodePayload{
			Count:  k,
			Target: key,
		}
		if err = dht.send(rpcid, fnode, target); err != nil {
			return nil, nil
		}

		msg, c, err := dht.recv(ch, done)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		switch v := msg.Payload.(type) {
		case *core.FindNodeRespPayload:
			dht.logf(LogDebug, "got %d nodes\n", len(v.Nodes))
			closest = v.Nodes
			err = dht.update(&core.NodeTriple{
				ID:   msg.Hdr.NodeID,
				IP:   msg.Hdr.NodeIP,
				Port: msg.Hdr.NodePort,
			})
			if err != nil {
				dht.log(LogErr, err)
				// Continue execution
			}
		case *core.ErrorPayload:
			return nil, errors.New(string(v.ErrorMsg))
		default:
			return nil, errors.New("received unexpected payload type")
		}
	}
	if len(closest) > k {
		dht.logf(LogDebug, "discarding %d nodes", len(closest)-k)
		closest = closest[:k]
	}
	var i int
	for _, n := range closest {
		dht.logf(LogDebug, "%s %s %d\n", hex.EncodeToString(n.ID), n.IP,
			n.Port)
		if !unique[string(n.ID)] {
			unique[string(n.ID)] = true
			closest[i] = n
			i++
		} else {
			dht.logf(LogDebug, "%s already found\n",
				hex.EncodeToString(n.ID))
		}

	}
	for j := i; j < len(closest); j++ {
		closest[j] = nil
	}
	return closest[:i], nil
}

func (dht *DHT) askStore(node *core.NodeTriple, key []byte, length uint64, value io.Reader) error {
	rpcid, ch, done, hc, err := dht.newHandler()
	if err != nil {
		return err
	}
	defer hc.Close()

	store := &core.StorePayload{
		Key:    key,
		Length: length,
	}
	if err := dht.send(rpcid, store, node); err != nil {
		return err
	}

	msg, c, err := dht.recv(ch, done)
	if err != nil {
		return err
	}
	defer c.Close()
	switch v := msg.Payload.(type) {
	case *core.PingPayload:
		break
	case *core.ErrorPayload:
		return errors.New(string(v.ErrorMsg))
	default:
		return errors.New("received unexpected payload type")
	}
	err = dht.update(&core.NodeTriple{
		ID:   msg.Hdr.NodeID,
		IP:   msg.Hdr.NodeIP,
		Port: msg.Hdr.NodePort,
	})
	if err != nil {
		dht.log(LogErr, err)
		// Continue execution
	}
	data := &core.DataPayload{
		Length: length,
		Value:  value,
	}
	return dht.send(rpcid, data, node)
}

func (dht *DHT) Load(key []byte) (value io.ReadCloser, length uint64, err error) {
	if len(key) != core.KeySize {
		return nil, 0, errors.New("invalid key")
	}
	if value, length, err = dht.storer.Load(key); err == nil {
		dht.logf(LogInfo, "file %s found locally\n",
			hex.EncodeToString(key))
		return
	}
	unique := make(map[string]bool)
	unique[string(dht.self.ID)] = true
	var found int32 = 0
	var data *core.DataPayload
	var c io.Closer
	cfg := &findConfig{
		Start:   []*core.NodeTriple{dht.self},
		Target:  key,
		K:       k,
		Workers: maxFindWorkers,
		Max:     maxFindHeapSize,
		Query: func(target *core.NodeTriple) []*core.NodeTriple {
			closest, ldata, lc, err := dht.queryLoad(key, target, unique)
			if err != nil {
				dht.log(LogErr, err)
				return nil
			}
			if ldata != nil {
				if atomic.CompareAndSwapInt32(&found, open, closed) {
					data = ldata
					c = lc
				} else {
					_ = lc.Close()
				}
			}
			return closest
		},
	}

	f, err := find(cfg)
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

func (dht *DHT) queryLoad(key []byte, target *core.NodeTriple, unique map[string]bool) ([]*core.NodeTriple, *core.DataPayload, io.Closer, error) {
	var closest []*core.NodeTriple
	var data *core.DataPayload

	if bytes.Equal(target.ID, dht.self.ID) {
		value, length, err := dht.storer.Load(key)
		if err != nil {
			closest, err := dht.rtable.Closest(key, k)
			if err != nil {
				return nil, nil, nil, err
			}
			return closest, nil, nil, nil
		}
		return nil, &core.DataPayload{
			Length: length,
			Value:  value,
		}, value, nil
	}
	rpcid, ch, done, hc, err := dht.newHandler()
	if err != nil {
		return nil, nil, nil, err
	}
	defer hc.Close()

	fval := &core.FindValuePayload{
		Key: key,
	}
	if err := dht.send(rpcid, fval, target); err != nil {
		return nil, nil, nil, err
	}

	msg, c, err := dht.recv(ch, done)
	if err != nil {
		return nil, nil, nil, err
	}
	if msg.Hdr.MsgType != core.TypeData {
		// When msg is TypeData, c is returned as the value closer.
		defer c.Close()
	}

	switch v := msg.Payload.(type) {
	case *core.DataPayload:
		data = v
		closest = []*core.NodeTriple{{ID: key}}
	case *core.FindNodeRespPayload:
		if len(v.Nodes) > k {
			dht.logf(LogDebug, "discarding %d nodes\n",
				len(v.Nodes)-k)
			v.Nodes = v.Nodes[:k]
		}
		var i int
		for _, n := range v.Nodes {
			dht.logf(LogDebug, "%s %s %d\n",
				hex.EncodeToString(n.ID), n.IP,
				n.Port)
			if !unique[string(n.ID)] {
				unique[string(n.ID)] = true
				v.Nodes[i] = n
				i++
			} else {
				dht.logf(LogDebug, "%s already found\n",
					hex.EncodeToString(n.ID))
			}
		}
		for j := i; j < len(v.Nodes); j++ {
			v.Nodes[j] = nil
		}
		closest = v.Nodes[:i]
	case *core.ErrorPayload:
		return nil, nil, nil, errors.New(string(v.ErrorMsg))
	default:
		fmt.Println("here1", msg.Hdr.MsgType)
		return nil, nil, nil, errors.New("received unexpected payload type")
	}
	err = dht.update(&core.NodeTriple{
		ID:   msg.Hdr.NodeID,
		IP:   msg.Hdr.NodeIP,
		Port: msg.Hdr.NodePort,
	})
	if err != nil {
		dht.log(LogErr, err)
	}
	return closest, data, c, nil
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
	defer hc.Close()

	fnode := &core.FindNodePayload{
		Count:  k,
		Target: dht.self.ID,
	}
	if err := dht.send(rpcid, fnode, target); err != nil {
		return err
	}

	msg, c, err := dht.recv(ch, done)
	if err != nil {
		return err
	}
	defer c.Close()
	switch v := msg.Payload.(type) {
	case *core.FindNodeRespPayload:
		if len(v.Nodes) > 0 && bytes.Equal(v.Nodes[0].ID, dht.self.ID) {
			// Target already knew about self.
			v.Nodes = v.Nodes[1:]
		}
		if len(v.Nodes) > k {
			v.Nodes = v.Nodes[:k]
		}
		if err := dht.update(target); err != nil {
			return err
		}
		for _, n := range v.Nodes {
			if err := dht.update(n); err != nil {
				dht.log(LogErr, err)
				// Continue execution
			}
		}
		return nil
	case *core.ErrorPayload:
		return errors.New(string(v.ErrorMsg))
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
			dht.log(LogNotice, err)
			continue
		}
		// XXX: verify remote addr matches msg addr?
		_ = addr
		if err = dht.enqueue(&msg, nil); err != nil {
			dht.log(LogErr, err)
			continue
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
			dht.log(LogErr, err)
			continue
		}
		var msg core.Message
		if err = msg.UnmarshalStream(conn, dht.priv); err != nil {
			dht.log(LogNotice, err)
			continue
		}
		// XXX: verify remote addr matches msg addr?
		// TODO: ensure conn is always closed in handler eventually,
		// even if session expires or sman is closed
		if err = dht.enqueue(&msg, conn); err != nil {
			dht.log(LogErr, err)
			continue
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
