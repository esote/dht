package dht

import (
	"bytes"
	"io"

	"github.com/esote/dht/core"
)

func (dht *DHT) findNode(id []byte, target *core.NodeTriple) []*core.NodeTriple {
	var closest []*core.NodeTriple
	var err error
	if bytes.Equal(target.ID, dht.self.ID) {
		closest, err = dht.rtable.Closest(id, k)
		if err != nil {
			dht.log(LogErr, err)
			return nil
		}
	} else {
		rpcid, ch, done, c, err := dht.newHandler()
		if err != nil {
			dht.log(LogErr, err)
			return nil
		}
		// TODO: check close value
		defer c.Close()

		fnode := &core.FindNodePayload{
			Count:  k,
			Target: id,
		}
		if err = dht.send(rpcid, fnode, target); err != nil {
			dht.log(LogErr, err)
			return nil
		}
		msg, err := dht.recv(ch, done)
		if err != nil {
			dht.log(LogErr, err)
			return nil
		}
		// TODO: check close value
		defer msg.Close()
		switch v := msg.Payload.(type) {
		case *core.FindNodeRespPayload:
			dht.logf(LogDebug, "got %d nodes", len(v.Nodes))
			closest = v.Nodes
			dht.update(&core.NodeTriple{
				ID:   msg.Hdr.ID,
				IP:   msg.Hdr.IP,
				Port: msg.Hdr.Port,
			})
		case *core.ErrorPayload:
			dht.log(LogWarning, "FIND_NODE gave error")
			dht.log(LogDebug, "FIND_NODE error:", string(v.Msg))
			return nil
		default:
			dht.log(LogErr, "received unexpected payload type")
			return nil
		}
	}
	if len(closest) > k {
		dht.logf(LogDebug, "discarding %d nodes", len(closest)-k)
		closest = closest[:k]
	}
	return closest
}

func (dht *DHT) askStore(target *core.NodeTriple, key []byte, length uint64, value io.Reader) bool {
	rpcid, ch, done, c, err := dht.newHandler()
	if err != nil {
		dht.log(LogErr, err)
		return false
	}
	// TODO: check close value
	defer c.Close()

	store := &core.StorePayload{
		Key:    key,
		Length: length,
	}
	if err = dht.send(rpcid, store, target); err != nil {
		dht.log(LogErr, err)
		return false
	}

	msg, err := dht.recv(ch, done)
	if err != nil {
		dht.log(LogErr, err)
		return false
	}
	// TODO: check close value
	defer msg.Close()
	switch v := msg.Payload.(type) {
	case *core.PingPayload:
		break
	case *core.ErrorPayload:
		dht.log(LogWarning, "STORE gave error")
		dht.log(LogDebug, "STORE error:", string(v.Msg))
		return false
	default:
		dht.log(LogErr, "received unexpected payload type")
		return false
	}
	dht.update(&core.NodeTriple{
		ID:   msg.Hdr.ID,
		IP:   msg.Hdr.IP,
		Port: msg.Hdr.Port,
	})
	data := &core.DataPayload{
		Length: length,
		Value:  value,
	}
	if err = dht.send(rpcid, data, target); err != nil {
		dht.log(LogErr, err)
	}
	return err == nil
}
