package session

import (
	"testing"
	"time"

	"github.com/esote/dht/core"
)

func TestManager(t *testing.T) {
	const c = 3
	ch := make(chan interface{}, c)
	done := make(chan struct{}, c)
	hf := func() *Handler {
		return &Handler{
			Ch:   ch,
			Done: done,
		}
	}
	m := NewManager(c, hf)
	rpcid := make([]byte, core.RPCIDSize)
	rpcid[0] = 1
	exp := time.Now().UTC().Add(5 * time.Second)
	msg := core.Message{
		Hdr: &core.Header{
			RPCID: rpcid,
			Time:  uint64(exp.Unix()),
		},
	}
	for i := 0; i < c+1; i++ {
		if err := m.Enqueue(string(rpcid), &msg, exp); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < c; i++ {
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ch:
			timer.Stop()
		case <-done:
			t.Fatal("closed incorrectly")
			timer.Stop()
		case <-timer.C:
			t.Fatal("no message recieved")
		}
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(5 * time.Millisecond)
	select {
	case <-done:
	case <-timer.C:
		t.Fatal("close not recieved")
	}
}
