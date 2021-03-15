package dht

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"sync"

	"github.com/esote/dht/core"
	"github.com/esote/dht/find"
	"github.com/esote/dht/util"
)

func (dht *DHT) Load(key []byte) (io.ReadCloser, uint64, error) {
	if len(key) != core.KeySize {
		return nil, 0, errors.New("invalid key")
	}

	var findOnce sync.Once
	var data *core.DataPayload
	id := key[:core.NodeIDSize]
	f, err := find.Find(&find.Config{
		Start:            []*core.NodeTriple{dht.self},
		Target:           id,
		Workers:          maxFindWorkers,
		MaxBacklogSize:   maxFindBacklogSize,
		MaxReturn:        maxFindReturn,
		MaxUniqueHistory: maxFindUniqueHistory,
		Query: func(target *core.NodeTriple) []*core.NodeTriple {
			closest, targetData := dht.findValue(key, target)
			if targetData != nil {
				findOnce.Do(func() {
					data = targetData
				})
				return []*core.NodeTriple{{ID: id}}
			}
			return closest
		},
	})
	if err != nil {
		return nil, 0, err
	}
	dht.addFinder(f)

	<-f.Done
	dht.removeFinder(f)

	if data == nil {
		return nil, 0, errors.New("value not found")
	}

	if closer, ok := data.Value.(io.Closer); ok {
		return util.JoinReadCloser(data.Value, closer), data.Length, nil
	}
	dht.log(LogErr, "data value missing closer")
	return ioutil.NopCloser(data.Value), data.Length, nil
}

func (dht *DHT) findValue(key []byte, target *core.NodeTriple) ([]*core.NodeTriple, *core.DataPayload) {
	id := key[:core.NodeIDSize]
	if bytes.Equal(target.ID, dht.self.ID) {
		value, length, err := dht.storer.Load(key)
		if err != nil {
			closest, err := dht.rtable.Closest(id, k)
			if err != nil {
				dht.log(LogErr, err)
				return nil, nil
			}
			return closest, nil
		}
		return nil, &core.DataPayload{
			Length: length,
			Value:  value,
		}
	}

	s, err := dht.newSession()
	if err != nil {
		dht.log(LogErr, err)
		return nil, nil
	}
	defer func() {
		if err = s.Close(); err != nil {
			dht.log(LogErr, err)
		}
	}()

	fval := &core.FindValuePayload{
		Key: key,
	}
	if err = s.send(fval, target); err != nil {
		dht.log(LogErr, err)
		return nil, nil
	}

	msg, err := s.recv()
	if err != nil {
		dht.log(LogErr, err)
		return nil, nil
	}
	if msg.Hdr.MsgType != core.TypeData {
		// Close immediately, DATA messages are the only expected stream
		// message.
		if err = msg.Close(); err != nil {
			dht.log(LogErr, err)
			return nil, nil
		}
	}

	switch v := msg.Payload.(type) {
	case *core.DataPayload:
		// Hide msg closer in value reader.
		v.Value = util.JoinReadCloser(v.Value, msg).(io.Reader)
		return nil, v
	case *core.FindNodeRespPayload:
		dht.logf(LogDebug, "got %d nodes", len(v.Nodes))
		if len(v.Nodes) > k {
			dht.logf(LogDebug, "discarding %d nodes", len(v.Nodes)-k)
			v.Nodes = v.Nodes[:k]
		}
		return v.Nodes, nil
	case *core.ErrorPayload:
		dht.log(LogDebug, "FIND_VALUE error:", string(v.Msg))
		return nil, nil
	default:
		dht.log(LogErr, "received unexpected payload type")
		return nil, nil
	}
}
