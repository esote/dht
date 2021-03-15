package dht

import (
	"github.com/esote/dht/core"
	"github.com/esote/dht/session"
)

func (dht *DHT) handlerFunc(rpcid []byte) *session.Handler {
	ch := make(chan *session.MessageCloser, 1)
	done := make(chan struct{}, 1)
	dht.handlers.Add(1)
	go dht.handle(&rpcSession{
		ch:    ch,
		done:  done,
		rpcid: rpcid,
		dht:   dht,
	})
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
func (dht *DHT) handle(s *rpcSession) {
	defer func() {
		if err := s.Close(); err != nil {
			dht.log(LogErr, err)
		}
	}()
	msg, err := s.recv()
	if err != nil {
		dht.log(LogErr, err)
		return
	}
	defer func() {
		if err := msg.Close(); err != nil {
			dht.log(LogErr, err)
		}
	}()

	target := &core.NodeTriple{
		ID:   msg.Hdr.ID,
		IP:   msg.Hdr.IP,
		Port: msg.Hdr.Port,
	}
	dht.update(target)

	switch v := msg.Payload.(type) {
	case *core.PingPayload:
		payload := &core.PingPayload{}
		if err := s.send(payload, target); err != nil {
			dht.log(LogErr, err)
		}
		return
	case *core.StorePayload:
		if err = dht.storer.Store(v.Key, v.Length, nil); err != nil {
			payload := &core.ErrorPayload{
				Msg: []byte("Value already stored"),
			}
			if err = s.send(payload, target); err != nil {
				dht.log(LogErr, err)
			}
			return
		}
		payload := &core.PingPayload{}
		if err = s.send(payload, target); err != nil {
			dht.log(LogErr, err)
			return
		}
		if msg, err = s.recv(); err != nil {
			dht.log(LogErr, err)
			return
		}
		defer func() {
			if err := msg.Close(); err != nil {
				dht.log(LogErr, err)
			}
		}()
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
			if err = s.send(payload, target); err != nil {
				dht.log(LogErr, err)
			}
			return
		}
		payload := &core.FindNodeRespPayload{
			Nodes: closest,
		}
		if err = s.send(payload, target); err != nil {
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
				if err = s.send(payload, target); err != nil {
					dht.log(LogErr, err)
				}
				return
			}
			payload := &core.FindNodeRespPayload{
				Nodes: closest,
			}
			if err = s.send(payload, target); err != nil {
				dht.log(LogErr, err)
			}
			return
		}
		defer func() {
			if err := value.Close(); err != nil {
				dht.log(LogErr, err)
			}
		}()
		payload := &core.DataPayload{
			Length: length,
			Value:  value,
		}
		if err = s.send(payload, target); err != nil {
			dht.log(LogErr, err)
		}
		return
	default:
		dht.log(LogDebug, "received unexpected payload type")
		return
	}
}
