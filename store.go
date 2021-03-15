package dht

import (
	"bytes"
	"errors"
	"io"

	"github.com/esote/dht/core"
	"github.com/esote/dht/find"
)

// Rereader returns a new reader for the same source, allowing its stream to be
// "reread".
type Rereader interface {
	Next() (io.ReadCloser, error)
}

func (dht *DHT) Store(key []byte, length uint64, value Rereader) error {
	if len(key) != core.KeySize {
		return errors.New("invalid key")
	}
	if length == 0 {
		return errors.New("nonpositive length")
	}
	if value == nil {
		return errors.New("value is nil")
	}

	id := key[:core.NodeIDSize]
	f, err := find.Find(&find.Config{
		Start:            []*core.NodeTriple{dht.self},
		Target:           id,
		Workers:          maxFindWorkers,
		MaxBacklogSize:   maxFindBacklogSize,
		MaxReturn:        maxFindReturn,
		MaxUniqueHistory: maxFindUniqueHistory,
		Query: func(target *core.NodeTriple) []*core.NodeTriple {
			return dht.findNode(id, target)
		},
	})
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
	for _, n := range closest {
		if err = dht.askStore(n, key, length, value); err != nil {
			dht.log(LogErr, err)
		}
	}
	return nil
}

func (dht *DHT) findNode(id []byte, target *core.NodeTriple) []*core.NodeTriple {
	if bytes.Equal(target.ID, dht.self.ID) {
		closest, err := dht.rtable.Closest(id, k)
		if err != nil {
			dht.log(LogErr, err)
			return nil
		}
		return closest
	}
	s, err := dht.newSession()
	if err != nil {
		dht.log(LogErr, err)
		return nil
	}
	defer func() {
		if err = s.Close(); err != nil {
			dht.log(LogErr, err)
		}
	}()
	fnode := &core.FindNodePayload{
		Count:  k,
		Target: id,
	}
	if err = s.send(fnode, target); err != nil {
		dht.log(LogErr, err)
		return nil
	}
	msg, err := s.recv()
	if err != nil {
		dht.log(LogErr, err)
		return nil
	}
	if err = msg.Close(); err != nil {
		dht.log(LogErr, err)
		return nil
	}
	switch v := msg.Payload.(type) {
	case *core.FindNodeRespPayload:
		dht.logf(LogDebug, "got %d nodes", len(v.Nodes))
		closest := v.Nodes
		if len(closest) > k {
			dht.logf(LogDebug, "discarding %d nodes", len(closest)-k)
			closest = closest[:k]
		}
		dht.update(&core.NodeTriple{
			ID:   msg.Hdr.ID,
			IP:   msg.Hdr.IP,
			Port: msg.Hdr.Port,
		})
		return closest
	case *core.ErrorPayload:
		dht.log(LogDebug, "FIND_NODE error:", string(v.Msg))
		return nil
	default:
		dht.log(LogErr, "received unexpected payload type")
		return nil
	}
}

func (dht *DHT) askStore(target *core.NodeTriple, key []byte, length uint64, value Rereader) (err error) {
	v, err := value.Next()
	if err != nil {
		return
	}
	defer func() {
		if err2 := v.Close(); err == nil {
			err = err2
		}
	}()
	dht.log(LogDebug, "storing in", nodeToString(target))

	if bytes.Equal(target.ID, dht.self.ID) {
		return dht.storer.Store(key, length, v)
	}

	s, err := dht.newSession()
	if err != nil {
		return
	}
	defer func() {
		if err2 := s.Close(); err == nil {
			err = err2
		}
	}()
	store := &core.StorePayload{
		Key:    key,
		Length: length,
	}
	if err = s.send(store, target); err != nil {
		return
	}
	msg, err := s.recv()
	if err != nil {
		return
	}
	if err = msg.Close(); err != nil {
		return
	}
	switch v := msg.Payload.(type) {
	case *core.PingPayload:
		break
	case *core.ErrorPayload:
		return errors.New(string(v.Msg))
	default:
		return errors.New("received unexpected payload type")
	}
	dht.update(&core.NodeTriple{
		ID:   msg.Hdr.ID,
		IP:   msg.Hdr.IP,
		Port: msg.Hdr.Port,
	})
	data := &core.DataPayload{
		Length: length,
		Value:  v,
	}
	return s.send(data, target)
}
