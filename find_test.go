package dht

// TODO: rewrite test for core.NodeTriple
/*
func TestFind(t *testing.T) {
	const target = 128
	cfg := &FindConfig{
		Start:   []interface{}{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		Target:  target,
		N:       10,
		Workers: 5,
		Max:     100,
		Cmp: func(a, b interface{}) int {
			// Sort by distance to target
			ad, bd := a.(int)-target, b.(int)-target
			if ad < 0 {
				ad = -ad
			}
			if bd < 0 {
				bd = -bd
			}
			switch {
			case ad < bd:
				return -1
			case ad > bd:
				return 1
			default:
				return 0
			}
		},
		Query: func(x interface{}) []interface{} {
			time.Sleep(20 * time.Millisecond)
			// 52% chance not to return data.
			if rand.Intn(100) < 52-1 {
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
	timer := time.NewTimer(5 * time.Second)
	select {
	case v := <-f.Done:
		timer.Stop()
		fmt.Println(v)
	case <-timer.C:
		t.Fatal("find ran out of time")
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}
*/
