package core

import (
	"math/bits"
)

// LCP computes the longest common prefix, in bits, between two node IDs. Panics
// if the length of x or y is incorrect.
func LCP(x, y []byte) int {
	if len(x) != NodeIDSize || len(y) != NodeIDSize {
		panic("LCP on invalid IDs")
	}
	for i := 0; i < NodeIDSize; i++ {
		if b := x[i] ^ y[i]; b != 0 {
			return i*8 + bits.LeadingZeros8(b)
		}
	}
	return NodeIDSize * 8
}

func leadingZeros(b []byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] != 0 {
			return i*8 + bits.LeadingZeros8(b[i])
		}
	}
	return len(b) * 8
}

func xor(dst, a, b []byte) {
	for i := 0; i < len(dst); i++ {
		dst[i] = a[i] ^ b[i]
	}
}
