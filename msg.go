package dht

import (
	"crypto/rand"
	"errors"
	"net"
	"time"

	"github.com/esote/dht/core"
	"github.com/esote/dht/session"
)

type rpcSession struct {
	ch    chan *session.MessageCloser
	done  chan struct{}
	rpcid []byte

	dht *DHT
}

func (dht *DHT) newSession() (*rpcSession, error) {
	rpcid := make([]byte, core.RPCIDSize)
	if _, err := rand.Read(rpcid); err != nil {
		return nil, err
	}
	ch := make(chan *session.MessageCloser, 1)
	done := make(chan struct{}, 1)
	handler := &session.Handler{
		Ch:   ch,
		Done: done,
	}
	dht.handlers.Add(1)
	exp := time.Now().Add(dht.fixedTimeout)
	if err := dht.sman.Register(rpcid, exp, handler); err != nil {
		dht.handlers.Done()
		close(done)
		close(ch)
		return nil, err
	}
	return &rpcSession{
		ch:    ch,
		done:  done,
		rpcid: rpcid,
		dht:   dht,
	}, nil
}

func (s *rpcSession) Close() error {
	defer s.dht.handlers.Done() // TODO: order after Remove?
	err := s.dht.sman.Remove(s.rpcid)
	close(s.done)
	close(s.ch)
	return err
}

func (s *rpcSession) recv() (*session.MessageCloser, error) {
	timer := time.NewTimer(s.dht.fixedTimeout)
	defer timer.Stop()
	select {
	case msg := <-s.ch:
		if msg == nil {
			return nil, errors.New("received nil message")
		}
		s.dht.logf(LogInfo, "recv %s from %s %d",
			msgTypeString(msg.Hdr.MsgType), msg.Hdr.IP,
			msg.Hdr.Port)
		return msg, nil
	case <-s.done:
		return nil, errors.New("session expired")
	case <-timer.C:
		return nil, errors.New("receive timeout expired")
	}
}

func (s *rpcSession) send(payload core.MessagePayload, target *core.NodeTriple) (err error) {
	exp := time.Now().Add(s.dht.fixedTimeout)
	msg := &core.Message{
		Version:  core.Version,
		BodyKind: payload.BodyKind(),
		Hdr: &core.Header{
			NetworkID: s.dht.networkId,
			MsgType:   payload.MsgType(),
			ID:        s.dht.self.ID,
			PuzDynX:   s.dht.x,
			IP:        s.dht.self.IP,
			Port:      s.dht.self.Port,
			RPCID:     s.rpcid,
			Time:      uint64(exp.Unix()),
		},
		Payload: payload,
	}
	s.dht.logf(LogInfo, "send %s to %s %d", msgTypeString(msg.Hdr.MsgType),
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
		defer func() {
			if err2 := conn.Close(); err == nil {
				err = err2
			}
		}()
		if err = conn.SetDeadline(time.Now().Add(s.dht.fixedTimeout)); err != nil {
			return err
		}
		packet, err := s.dht.codec.EncodeFixed(msg, s.dht.priv, target.ID)
		if err != nil {
			return err
		}
		_, err = conn.Write(packet)
		return err
	case core.KindStream:
		addr := &net.TCPAddr{
			IP:   target.IP,
			Port: int(target.Port),
		}
		conn, err := net.DialTCP("tcp", nil, addr)
		if err != nil {
			return err
		}
		defer func() {
			if err2 := conn.Close(); err == nil {
				err = err2
			}
		}()
		if err = conn.SetDeadline(time.Now().Add(s.dht.streamTimeout)); err != nil {
			return err
		}
		return s.dht.codec.EncodeStream(msg, conn, s.dht.priv, target.ID)
	default:
		return errors.New("message body kind unsupported")
	}
}
