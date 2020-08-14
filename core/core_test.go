package core

import "testing"

func TestLCP(t *testing.T) {
	var x, y ID
	x[4] = 0b10001000
	y[4] = 0b10000000
	const lcp = (3+1)*8 + 4
	if got := x.LCP(&y); got != lcp {
		t.Fatalf("want %d, got %d", lcp, got)
	}
	if x.LCP(&y) != y.LCP(&x) {
		t.Fatal("LCP not commutative")
	}
	if x.LCP(&x) != IDLen*8-1 {
		t.Fatal("prefix of (x,x) not maximal")
	}
}
