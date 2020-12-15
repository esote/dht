package find

import (
	"math/rand"
	"testing"
	"time"

	"github.com/esote/dht/core"
)

func TestFind(t *testing.T) {
	target := make([]byte, core.NodeIDSize)
	target[31] = 255

	start := make([]byte, core.NodeIDSize)

	cfg := &Config{
		Start: []*core.NodeTriple{
			{
				ID: start,
			}},
		Target:           target,
		Workers:          5,
		MaxReturn:        10,
		MaxBacklogSize:   10,
		MaxUniqueHistory: 255,
		Query: func(target *core.NodeTriple) []*core.NodeTriple {
			// 52% chance not to return data
			if rand.Intn(100) < 52-1 {
				return nil
			}
			nodes := make([]*core.NodeTriple, rand.Intn(6))
			for i := range nodes {
				nodes[i] = &core.NodeTriple{
					ID: make([]byte, core.NodeIDSize),
				}
				nodes[i].ID[31] = byte(rand.Intn(int(^byte(0))))
			}
			return nodes
		},
	}

	f, err := Find(cfg)
	if err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(time.Second)
	select {
	case v := <-f.Done:
		timer.Stop()
		for i := 1; i < len(v); i++ {
			if core.LCP(target, v[i-1].ID) < core.LCP(target, v[i].ID) {
				t.Fatal("incorrect node ID order")
			}
		}
	case <-timer.C:
		t.Fatal("find ran out of time")
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}
