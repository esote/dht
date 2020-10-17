package dht

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/esote/dht/core"
)

func (dht *DHT) recv(ch chan interface{}, done chan struct{}) (*core.Message, io.Closer) {
	timer := time.NewTimer(dht.timeout)
	defer timer.Stop()
	select {
	case v := <-ch:
		if v == nil {
			panic("received nil message")
		}
		w, ok := v.(*wrappedMsg)
		if !ok {
			panic("received value of wrong type")
		}
		if w.c == nil {
			w.c = nopCloser{}
		}
		return w.msg, w.c
	case <-done:
		// Session expired and garbage-collected by session manager.
		return nil, nil
	case <-dht.done:
		// DHT is closed.
		return nil, nil
	case <-timer.C:
		// Recv timeout.
		return nil, nil
	}
}

// wrappedMsg encloses a message with some context.
type wrappedMsg struct {
	msg *core.Message

	// Closer used for TCP messages to have handlers close the stream after
	// it is used.
	c io.Closer
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// enqueue message using wrappedMsg, c may be nil
func (dht *DHT) enqueue(msg *core.Message, c io.Closer) error {
	key := string(msg.Hdr.RPCID)
	exp := time.Unix(int64(msg.Hdr.Time), 0)
	w := &wrappedMsg{
		msg: msg,
		c:   c,
	}
	return dht.sman.Enqueue(key, w, exp)
}

func (dht *DHT) send(rpcid []byte, payload core.MessagePayload, target *Node) error {
	exp := time.Now().Add(dht.timeout)
	msg := &core.Message{
		Version:  core.Version,
		BodyKind: payload.BodyKind(),
		Hdr: &core.Header{
			MsgType:  payload.MsgType(),
			NodeID:   dht.publ,
			PuzDynX:  dht.x,
			NodeIP:   dht.ip,
			NodePort: dht.port,
			RPCID:    rpcid,
			Time:     uint64(exp.Unix()),
		},
		Payload: payload,
	}
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
		defer conn.Close()
		if err = conn.SetDeadline(time.Now().Add(dht.timeout)); err != nil {
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
		defer conn.Close()
		// sending file can have a larger timeout than fixed size sends
		if err = conn.SetDeadline(time.Now().Add(dht.timeout)); err != nil {
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
