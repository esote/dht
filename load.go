package dht

import (
	"bytes"
	"io"

	"github.com/esote/dht/core"
)

func (dht *DHT) findValue(key []byte, target *core.NodeTriple) ([]*core.NodeTriple, *core.DataPayload, io.Closer) {
	id := key[:core.NodeIDSize]
	if bytes.Equal(target.ID, dht.self.ID) {
		value, length, err := dht.storer.Load(key)
		if err != nil {
			closest, err := dht.rtable.Closest(id, k)
			if err != nil {
				dht.log(LogErr, err)
				return nil, nil, nil
			}
			return closest, nil, nil
		}
		return nil, &core.DataPayload{
			Length: length,
			Value:  value,
		}, value
	}
	rpcid, ch, done, c, err := dht.newHandler()
	if err != nil {
		dht.log(LogErr, err)
		return nil, nil, nil
	}
	// TODO: check close value
	defer c.Close()

	fval := &core.FindValuePayload{
		Key: key,
	}
	if err = dht.send(rpcid, fval, target); err != nil {
		dht.log(LogErr, err)
		return nil, nil, nil
	}

	msg, err := dht.recv(ch, done)
	if err != nil {
		dht.log(LogErr, err)
		return nil, nil, nil
	}
	if msg.Hdr.MsgType != core.TypeData {
		// Close immediately, DATA messages are the only expected stream
		// message.
		_ = msg.Close()
	}

	switch v := msg.Payload.(type) {
	case *core.DataPayload:
		return nil, v, msg
	case *core.FindNodeRespPayload:
		dht.logf(LogDebug, "got %d nodes", len(v.Nodes))
		if len(v.Nodes) > k {
			dht.logf(LogDebug, "discarding %d nodes",
				len(v.Nodes)-k)
			v.Nodes = v.Nodes[:k]
		}
		return v.Nodes, nil, nil
	case *core.ErrorPayload:
		dht.log(LogWarning, "FIND_VALUE gave error")
		dht.log(LogDebug, "FIND_VALUE error:", string(v.Msg))
		return nil, nil, nil
	default:
		dht.log(LogErr, "received unexpected payload type")
		return nil, nil, nil
	}
}
