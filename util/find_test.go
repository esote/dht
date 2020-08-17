package util

import (
	"math/rand"
	"testing"
	"time"
)

func TestFind(t *testing.T) {
	cfg := &FindConfig{
		Start:   []interface{}{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		Target:  128,
		Workers: 5,
		Max:     100,
		Cmp: func(a, b interface{}) int {
			switch {
			case a.(int) < b.(int):
				return -1
			case a.(int) > b.(int):
				return 1
			default:
				return 0
			}
		},
		Query: func(x interface{}) []interface{} {
			time.Sleep(20 * time.Millisecond)
			// 55% chance not to return data.
			if rand.Intn(100) > 55-1 {
				return []interface{}{}
			}
			vals := make([]interface{}, rand.Intn(5))
			for i := range vals {
				vals[i] = rand.Intn(255)
			}
			return vals
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
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		if v != nil && v != cfg.Target {
			t.Fatal("found wrong value")
		}
	case <-timer.C:
		t.Fatal("find ran out of time")
	}
}
