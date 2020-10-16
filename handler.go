package dht

import (
	"github.com/esote/dht/core"
	"github.com/esote/dht/session"
)

func (dht *DHT) handlerFunc() *session.Handler {
	ch := make(chan *core.Message, 1)
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
*/

// TODO: log errors
func (dht *DHT) handle(ch chan *core.Message, done chan struct{}) {
	defer dht.handlers.Done()
	defer close(ch)
	defer close(done)
	msg := dht.recv(ch, done)
	if msg == nil {
		// Channel should have a message prior to starting the handler.
		return
	}
	// TODO: update rtable with new node
	rpcid := msg.Hdr.RPCID
	// Manually remove session if returning prior to expiration.
	defer dht.sman.Remove(string(rpcid))
	// Target node to converse with.
	target := &Node{
		ID:   msg.Hdr.NodeID,
		IP:   msg.Hdr.NodeIP,
		Port: msg.Hdr.NodePort,
	}
	switch v := msg.Payload.(type) {
	case *core.PingPayload:
		// Respond with ping.
		payload := &core.PingPayload{}
		_ = dht.send(rpcid, payload, target)
		return
	case *core.StorePayload:
		// Check if we can store the value: if not, respond with an
		// error, otherwise respond with a ping and wait for a data msg.
		key, length := v.Key, v.Length
		if err := dht.storer.Store(key, length, nil); err != nil {
			payload := &core.ErrorPayload{
				ErrorMsg: []byte("Value already stored"),
			}
			_ = dht.send(rpcid, payload, target)
			return
		}
		payload := &core.PingPayload{}
		if err := dht.send(rpcid, payload, target); err != nil {
			return
		}
		if msg = dht.recv(ch, done); msg == nil {
			return
		}
		switch v := msg.Payload.(type) {
		case *core.DataPayload:
			// TODO: need to close v.Value?
			if v.Length != length {
				return
			}
			_ = dht.storer.Store(key, length, v.Value)
			return
		default:
			// Unexpected message.
			return
		}
		return
	case *core.FindNodePayload:
		// Respond with list of nodes, or error.
		return
	case *core.FindValuePayload:
		// Respond with value if we have it, otherwise respond with
		// FindNodeResp of nodes closest to value, otherwise respond
		// with error.
		return
	default:
		// Unexpected message.
		return
	}
}
