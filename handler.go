package dht

import (
	"github.com/esote/dht/core"
	"github.com/esote/dht/session"
)

func (dht *DHT) handlerFunc() *session.Handler {
	ch := make(chan *session.MessageCloser, 1)
	done := make(chan struct{}, 1)
	dht.handlers.Add(1)
	go dht.handle(ch, done)
	return &session.Handler{
		Ch:   ch,
		Done: done,
	}
}

/*
DHT may receive:

	PING:
		Respond with PING
	STORE:
		If we can store: respond with PING
			Receive DATA
		Otherwise: ERROR
	FIND_NODE:
		If we can locate nodes: respond with FIND_NODE_RESP
		Otherwise: ERROR
	FIND_VALUE:
		If we have value: respond with DATA
		Otherwise if we can locate nodes: respond with FIND_NODE_RESP
		Otherwise: ERROR
*/
func (dht *DHT) handle(ch chan *session.MessageCloser, done chan struct{}) {
	defer close(done)
	defer close(ch)
	defer dht.handlers.Done()

	msg, err := dht.recv(ch, done)
	if err != nil {
		dht.log(LogErr, err)
		return
	}
	// TODO: check close value
	defer msg.Close()
	rpcid := msg.Hdr.RPCID
	// TODO: check close value
	defer dht.sman.Remove(string(rpcid))

	target := &core.NodeTriple{
		ID:   msg.Hdr.ID,
		IP:   msg.Hdr.IP,
		Port: msg.Hdr.Port,
	}
	dht.update(target)

	switch v := msg.Payload.(type) {
	case *core.PingPayload:
		payload := &core.PingPayload{}
		if err := dht.send(rpcid, payload, target); err != nil {
			dht.log(LogErr, err)
		}
		return
	case *core.StorePayload:
		if err = dht.storer.Store(v.Key, v.Length, nil); err != nil {
			payload := &core.ErrorPayload{
				Msg: []byte("Value already stored"),
			}
			if err = dht.send(rpcid, payload, target); err != nil {
				dht.log(LogErr, err)
			}
			return
		}
		payload := &core.PingPayload{}
		if err = dht.send(rpcid, payload, target); err != nil {
			dht.log(LogErr, err)
			return
		}
		if msg, err = dht.recv(ch, done); err != nil {
			dht.log(LogErr, err)
			return
		}
		// TODO: check close value
		defer msg.Close()
		switch v2 := msg.Payload.(type) {
		case *core.DataPayload:
			if v2.Length != v.Length {
				dht.log(LogWarning, "DATA length didn't match STORE length")
				return
			}
			if err = dht.storer.Store(v.Key, v.Length, v2.Value); err != nil {
				dht.log(LogErr, err)
			}
			return
		default:
			dht.log(LogDebug, "received unexpected payload type")
			return
		}
	case *core.FindNodePayload:
		if v.Count > k {
			// TODO: log
			v.Count = k
		} else if v.Count == 0 {
			dht.log(LogDebug, "recv find node with zero count")
			return
		}
		closest, err := dht.rtable.Closest(v.Target, k)
		if err != nil {
			dht.log(LogErr, err)
			payload := &core.ErrorPayload{
				Msg: []byte("Failed to find nodes"),
			}
			if err = dht.send(rpcid, payload, target); err != nil {
				dht.log(LogErr, err)
			}
			return
		}
		payload := &core.FindNodeRespPayload{
			Nodes: closest,
		}
		if err = dht.send(rpcid, payload, target); err != nil {
			dht.log(LogErr, err)
		}
		return
	case *core.FindValuePayload:
		id := v.Key[:core.NodeIDSize]
		value, length, err := dht.storer.Load(v.Key)
		if err != nil {
			closest, err := dht.rtable.Closest(id, k)
			if err != nil {
				dht.log(LogErr, err)
				payload := &core.ErrorPayload{
					Msg: []byte("Failed to find nodes"),
				}
				if err = dht.send(rpcid, payload, target); err != nil {
					dht.log(LogErr, err)
				}
				return
			}
			payload := &core.FindNodeRespPayload{
				Nodes: closest,
			}
			if err = dht.send(rpcid, payload, target); err != nil {
				dht.log(LogErr, err)
			}
			return
		}
		// TODO: check close value
		defer value.Close()
		payload := &core.DataPayload{
			Length: length,
			Value:  value,
		}
		if err = dht.send(rpcid, payload, target); err != nil {
			dht.log(LogErr, err)
		}
		return
	default:
		dht.log(LogDebug, "received unexpected payload type")
		return
	}
}
