// DHT is an experiment to write a distributed hash table following the Kademlia
// paper https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf.
package dht

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/esote/dht/core"
)

const (
	// NetworkIdentity is the IDENT header value used to identify this
	// specific implementation of PROTOCOL.
	NetworkIdentity = "dht-esote-v1"

	// K is the count of nodes in a given K bucket, as used by DHT.
	K = 20

	// FindNodeMaxCount places a limit on the maximum nodes to query when
	// the DHT receives a FIND_NODES request.
	FindNodeMaxCount = K
)

func init() {
	// Ensure NetworkIdentity's length won't overflow IDENT_LEN.
	if len(NetworkIdentity) > int(^uint8(0)) {
		panic("network identity too large")
	}
}

// DHT is a distributed hash table as defined in the Kademlia paper. DHT is safe
// to use concurrently.
type DHT struct {
	rtable  RTable
	storer  Storer
	network Network

	self *core.Node

	cfg *Config

	wg   sync.WaitGroup
	quit chan struct{}
}

// Config is used to configure DHT in NewDHT.
type Config struct {
	NewID   bool
	Workers int
	// TODO: logger interface to pass nonfatal errors.
	// TODO: bootstrap nodes
}

// NewDHT constructs a SQLite3-backed DHT using a given storer and network.
func NewDHT(dir string, storer Storer, network Network, cfg *Config) (*DHT, error) {
	if storer == nil {
		return nil, errors.New("dht: storer is nil")
	}
	if network == nil {
		return nil, errors.New("dht: network is nil")
	}
	if cfg == nil {
		cfg = &Config{
			NewID:   false,
			Workers: 5,
		}
	} else if cfg.Workers <= 0 {
		return nil, errors.New("dht: must have at least one worker")
	}
	var self core.ID
	if cfg.NewID {
		f, err := os.OpenFile(filepath.Join(dir, "self"),
			os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		self, err = core.NewID()
		if err != nil {
			return nil, err
		}
		if _, err = f.Write(self[:]); err != nil {
			return nil, err
		}
	} else {
		f, err := os.Open(filepath.Join(dir, "self"))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if _, err = f.Read(self[:]); err != nil {
			return nil, err
		}
	}
	host, port, err := net.SplitHostPort(network.Addr().String())
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("dht: network address is not an IP")
	}
	if ip = ip.To16(); ip == nil {
		return nil, errors.New("dht: network IP is malformed")
	}
	nport, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	dht := &DHT{
		storer:  storer,
		network: network,
		self: &core.Node{
			ID:   self,
			Port: uint16(nport),
			IP:   ip,
		},
		cfg:  cfg,
		quit: make(chan struct{}, cfg.Workers),
	}
	rt, err := NewSqlite3RTable(&self, K, dir, dht.ping)
	if err != nil {
		_ = dht.Close()
		return nil, err
	}
	dht.rtable = rt
	dht.wg.Add(cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		go dht.listen()
	}
	return dht, nil
}

// Load a value based on a key.
func (dht *DHT) Load(key *core.ID) (io.Reader, error) {
	// TODO: concurrently call FIND_VALUE
	return nil, nil
}

// Store a key-value pair on the network (either locally or distributed).
func (dht *DHT) Store(key *core.ID, value io.Reader) error {
	// TODO: call STORE on self, and on some other nodes.
	return nil
}

// Close the DHT.
func (dht *DHT) Close() error {
	var err error
	if dht.rtable != nil {
		err = dht.rtable.Close()
	}
	for i := 0; i < dht.cfg.Workers; i++ {
		dht.quit <- struct{}{}
	}
	dht.wg.Wait()
	close(dht.quit)
	return err
}

func (dht *DHT) listen() {
	defer dht.wg.Done()
	for {
		select {
		case <-dht.quit:
			return
		default:
		}
		conn, err := dht.network.Accept()
		if err != nil { // TODO: log?
			continue
		}
		_ = dht.receive(conn) // TODO: log?
	}
}

func (dht *DHT) receive(conn net.Conn) (err error) {
	defer conn.Close()
	req, err := core.NewMessage(conn)
	if err != nil {
		return
	}
	if err = dht.rtable.Store(req.Hdr.Node); err != nil {
		return
	}
	resp := &core.Message{
		Hdr: dht.baseHeader(),
	}
	resp.Hdr.RPCID = req.Hdr.RPCID
	switch v := req.Payload.(type) {
	case *core.Ping:
		resp.Payload = &core.Ping{}
	case *core.Store:
		if err = dht.storer.Store(&v.Key, v.Length, v.Value); err != nil {
			resp.Payload = core.NewErrorStr("Store value failed")
		}
		return nil
	case *core.FindNode:
		if v.Count > FindNodeMaxCount {
			v.Count = FindNodeMaxCount
		}
		nodes, err := dht.rtable.Closest(&v.Target, int(v.Count))
		if err != nil {
			resp.Payload = core.NewErrorStr("Finding nodes failed")
			break
		}
		resp.Payload = &core.FindNodeResp{
			Nodes: nodes,
		}
	case *core.FindNodeResp:
		return errors.New("dht: unexpected FIND_NODE_RESP")
	case *core.FindValue:
		value, length, err := dht.storer.Load(&v.Key, v.Offset, v.Length)
		if err == ErrStorerNotExist {
			length = 0
		} else if err != nil {
			resp.Payload = core.NewErrorStr("Load value failed")
			break
		}
		if c, ok := value.(io.Closer); ok {
			defer c.Close()
		}
		resp.Payload = &core.FindValueResp{
			Length: length,
			Value:  value,
		}
	case *core.FindValueResp:
		return errors.New("dht: unexpected FIND_VALUE_RESP")
	case *core.Error:
		return errors.New("dht: unexpected ERROR")
	default:
		return errors.New("dht: payload type invalid")
	}
	resp.Hdr.Type = resp.Payload.Type()
	return resp.Encode(conn)
}

func (dht *DHT) baseHeader() *core.Header {
	return &core.Header{
		Magic:          core.Magic,
		IdentityLength: uint8(len(NetworkIdentity)),
		Identity:       []byte(NetworkIdentity),
		Node:           dht.self,
	}
}

func (dht *DHT) ping(n *core.Node) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	ok = dht.pingInner(n)
	return
}

func (dht *DHT) pingInner(n *core.Node) bool {
	port := strconv.FormatUint(uint64(n.Port), 10)
	addr := net.JoinHostPort(n.IP.String(), port)
	conn, err := dht.network.Dial(addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	req := &core.Message{
		Hdr:     dht.baseHeader(),
		Payload: &core.Ping{},
	}
	if req.Hdr.RPCID, err = core.NewID(); err != nil {
		return false
	}
	if err = req.Encode(conn); err != nil {
		return false
	}
	resp, err := core.NewMessage(conn)
	if err != nil {
		return false
	}
	return resp.Hdr.Type == core.TypePing && resp.Hdr.RPCID == req.Hdr.RPCID
}
