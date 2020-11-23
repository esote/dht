package dht

import (
	"encoding/hex"

	"github.com/esote/dht/core"
	"github.com/esote/dht/rtable"
)

/*

Try to add a new node to the RTable. If the RTable is full, ping the oldest node
to see if it is still alive. If it is alive, move the oldest node to the back,
otherwise remove the oldest node and add the new node.

*/
func (dht *DHT) update(n *core.NodeTriple) error {
	dht.logf(LogDebug, "update %s %s %d\n", hex.EncodeToString(n.ID),
		n.IP, n.Port)
	// TODO: mutex
	if err := dht.rtable.Store(n); err != rtable.ErrRTableFull {
		return err
	}
	oldest, err := dht.rtable.Oldest(n.ID)
	if err != nil {
		return err
	}

	rpcid, ch, done, hc, err := dht.newHandler()
	if err != nil {
		return err
	}
	defer hc.Close()

	payload := &core.PingPayload{}
	if err = dht.send(rpcid, payload, oldest); err != nil {
		return err
	}

	msg, c, err := dht.recv(ch, done)
	if err == nil {
		_ = c.Close()
	}
	if err == nil && msg.Hdr.MsgType == core.TypePing {
		// Oldest node is alive.
		return dht.rtable.Store(oldest)
	}
	// Oldest node is dead.
	if err = dht.rtable.Remove(oldest.ID); err != nil {
		return err
	}
	return dht.rtable.Store(n)
}
