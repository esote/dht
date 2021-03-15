package dht

import (
	"github.com/esote/dht/core"
	"github.com/esote/dht/rtable"
)

/*

Try to add a new node to the RTable. If the RTable is full, ping the oldest node
to see if it is still alive. If it is alive, move the oldest node to the back,
otherwise remove the oldest node and add the new node.

*/
func (dht *DHT) update(n *core.NodeTriple) {
	dht.updatePool.Enlist(true, func(args ...interface{}) {
		if err := dht.updateInner(args[0].(*core.NodeTriple)); err != nil {
			dht.log(LogErr, err)
		} else {
			dht.log(LogDebug, "update", nodeToString(n))
		}
	}, n)
}

func (dht *DHT) updateInner(n *core.NodeTriple) (err error) {
	if err = dht.rtable.Store(n); err != rtable.ErrRTableFull {
		return
	}
	oldest, err := dht.rtable.Oldest(n.ID)
	if err != nil {
		return
	}

	s, err := dht.newSession()
	if err != nil {
		return
	}
	defer func() {
		if err2 := s.Close(); err == nil {
			err = err2
		}
	}()

	payload := &core.PingPayload{}
	if err = s.send(payload, oldest); err != nil {
		return
	}

	msg, err := s.recv()
	if err == nil {
		// Close immediately, no stream message expected.
		if err = msg.Close(); err != nil {
			return
		}
	}
	if err == nil && msg.Hdr.MsgType == core.TypePing {
		// Oldest node is alive.
		return dht.rtable.Store(oldest)
	}

	// Oldest node is not alive, unable to receive ping.
	return dht.rtable.ReplaceOldest(n)
}
