package dht

import (
	"github.com/esote/dht/core"
	"github.com/esote/dht/session"
)

func (dht *DHT) handlerFunc() *session.Handler {
	ch := make(chan interface{}, 1)
	done := make(chan struct{}, 1)
	dht.handlers.Add(1)
	go dht.handle(ch, done)
	return &session.Handler{
		Ch:   ch,
		Done: done,
	}
}

/*
handle:
	->ping
		<-ping|
	->store
		<-ping
			->data|
		<-error|
	->find_node
		<-find_node_resp|
		<-error|
	->find_value
		<-data|
		<-find_node_resp|
		<-error|
*/
func (dht *DHT) handle(ch chan interface{}, done chan struct{}) {
	defer dht.handlers.Done()
	defer close(ch)
	defer close(done)
	msg, c, err := dht.recv(ch, done)
	if err != nil {
		// Channel should have a message prior to starting the handler.
		dht.log(LogErr, err)
		return
	}
	defer c.Close()
	rpcid := msg.Hdr.RPCID
	// Manually remove session if returning prior to expiration.
	defer dht.sman.Remove(string(rpcid))
	// Target node to converse with.
	target := &core.NodeTriple{
		ID:   msg.Hdr.NodeID,
		IP:   msg.Hdr.NodeIP,
		Port: msg.Hdr.NodePort,
	}
	// TODO: add to rtable asyncronously while executing handle?
	if err := dht.update(target); err != nil {
		dht.log(LogErr, err)
		// Continue execution
	}
	switch v := msg.Payload.(type) {
	case *core.PingPayload:
		// Respond with ping.
		payload := &core.PingPayload{}
		if err := dht.send(rpcid, payload, target); err != nil {
			dht.log(LogErr, err)
		}
		return
	case *core.StorePayload:
		// Check if we can store the value: if not, respond with an
		// error, otherwise respond with a ping and wait for a data msg.
		key, length := v.Key, v.Length
		if err := dht.storer.Store(key, length, nil); err != nil {
			payload := &core.ErrorPayload{
				ErrorMsg: []byte("Value already stored"),
			}
			if err = dht.send(rpcid, payload, target); err != nil {
				dht.log(LogErr, err)
			}
			return
		}
		payload := &core.PingPayload{}
		if err := dht.send(rpcid, payload, target); err != nil {
			dht.log(LogErr, err)
			return
		}
		if msg, c, err = dht.recv(ch, done); err != nil {
			dht.log(LogErr, err)
			return
		}
		defer c.Close()
		switch v := msg.Payload.(type) {
		case *core.DataPayload:
			if v.Length != length {
				return
			}
			if err := dht.storer.Store(key, length, v.Value); err != nil {
				dht.log(LogErr, err)
			}
			return
		default:
			dht.log(LogDebug, "received unexpected payload type")
			return
		}
	case *core.FindNodePayload:
		// Respond with list of nodes, or error.
		if v.Count > k {
			v.Count = k
		} else if v.Count == 0 {
			dht.log(LogNotice, "recv find node with zero count")
			return
		}
		closest, err := dht.rtable.Closest(v.Target, k)
		if err != nil {
			dht.log(LogErr, err)
			payload := &core.ErrorPayload{
				ErrorMsg: []byte("Failed to find nodes"),
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
		// Respond with value if we have it, otherwise respond with list
		// of closest nodes.
		value, length, err := dht.storer.Load(v.Key)
		if err != nil {
			closest, err := dht.rtable.Closest(v.Key, k)
			if err != nil {
				dht.log(LogErr, err)
				payload := &core.ErrorPayload{
					ErrorMsg: []byte("Failed to find nodes"),
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
