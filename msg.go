package dht

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
	"time"

	"github.com/esote/dht/core"
	"github.com/esote/dht/session"
)

func msgTypeString(t uint8) string {
	switch t {
	case core.TypePing:
		return "PING"
	case core.TypeStore:
		return "STORE"
	case core.TypeData:
		return "DATA"
	case core.TypeFindNode:
		return "FIND_NODE"
	case core.TypeFindNodeResp:
		return "FIND_NODE_RESP"
	case core.TypeFindValue:
		return "FIND_VALUE"
	case core.TypeError:
		return "ERROR"
	default:
		return "<nil>"
	}
}

type hcloser struct {
	ch    chan *session.MessageCloser
	done  chan struct{}
	rpcid string
	dht   *DHT
}

func (h *hcloser) Close() error {
	err := h.dht.sman.Remove(h.rpcid)
	h.dht.handlers.Done()
	close(h.done)
	close(h.ch)
	return err
}

func (dht *DHT) newHandler() ([]byte, <-chan *session.MessageCloser, <-chan struct{}, io.Closer, error) {
	rpcid := make([]byte, core.RPCIDSize)
	if _, err := rand.Read(rpcid); err != nil {
		return nil, nil, nil, nil, err
	}
	ch := make(chan *session.MessageCloser, 1)
	done := make(chan struct{}, 1)
	handler := &session.Handler{
		Ch:   ch,
		Done: done,
	}
	dht.handlers.Add(1)
	exp := time.Now().Add(dht.fixedTimeout)
	if err := dht.sman.Register(string(rpcid), exp, handler); err != nil {
		dht.handlers.Done()
		close(done)
		close(ch)
		return nil, nil, nil, nil, err
	}
	return rpcid, ch, done, &hcloser{ch, done, string(rpcid), dht}, nil
}

func (dht *DHT) recv(ch <-chan *session.MessageCloser, done <-chan struct{}) (*session.MessageCloser, error) {
	timer := time.NewTimer(dht.fixedTimeout)
	defer timer.Stop()
	select {
	case msg := <-ch:
		if msg == nil {
			return nil, errors.New("received nil message")
		}
		dht.logf(LogInfo, "recv %s from %s %d",
			msgTypeString(msg.Hdr.MsgType), msg.Hdr.IP,
			msg.Hdr.Port)
		return msg, nil
	case <-done:
		// Session expired and garbage-collected by session manager.
		return nil, errors.New("session expired")
	case <-timer.C:
		return nil, errors.New("receive timeout expired")
	}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func (dht *DHT) send(rpcid []byte, payload core.MessagePayload, target *core.NodeTriple) error {
	exp := time.Now().Add(dht.fixedTimeout)
	msg := &core.Message{
		Version:  core.Version,
		BodyKind: payload.BodyKind(),
		Hdr: &core.Header{
			NetworkID: dht.networkId,
			MsgType:   payload.MsgType(),
			ID:        dht.self.ID,
			PuzDynX:   dht.x,
			IP:        dht.self.IP,
			Port:      dht.self.Port,
			RPCID:     rpcid,
			Time:      uint64(exp.Unix()),
		},
		Payload: payload,
	}
	dht.logf(LogInfo, "send %s to %s %d", msgTypeString(msg.Hdr.MsgType),
		target.IP, target.Port)
	switch msg.BodyKind {
	case core.KindFixed:
		addr := &net.UDPAddr{
			IP:   target.IP,
			Port: int(target.Port),
		}
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			return err
		}
		// TODO: check close value
		defer conn.Close()
		if err = conn.SetDeadline(time.Now().Add(dht.fixedTimeout)); err != nil {
			return err
		}
		packet, err := msg.MarshalFixed(dht.priv, target.ID)
		if err != nil {
			return err
		}
		if _, err = conn.Write(packet); err != nil {
			return err
		}
	case core.KindStream:
		addr := &net.TCPAddr{
			IP:   target.IP,
			Port: int(target.Port),
		}
		conn, err := net.DialTCP("tcp", nil, addr)
		if err != nil {
			return err
		}
		// TODO: check close value
		defer conn.Close()
		if err = conn.SetDeadline(time.Now().Add(dht.streamTimeout)); err != nil {
			return err
		}
		if err = msg.MarshalStream(conn, dht.priv, target.ID); err != nil {
			return err
		}
	default:
		return errors.New("message body kind unsupported")
	}
	return nil
}
