package dht

import (
	"errors"
	"net"
	"time"

	"github.com/esote/dht/core"
)

func (dht *DHT) recv(ch chan *core.Message, done chan struct{}) *core.Message {
	timer := time.NewTimer(dht.timeout)
	defer timer.Stop()
	select {
	case msg := <-ch:
		return msg
	case <-done:
		// Session expired and garbage-collected by session manager.
		return nil
	case <-dht.done:
		// DHT is closed.
		return nil
	case <-timer.C:
		// Recv timeout.
		return nil
	}
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
