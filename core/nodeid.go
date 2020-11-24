package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"math/bits"

	"golang.org/x/crypto/sha3"
)

const (
	c1 = 2 // 23
	c2 = 2 // 24
)

func NewNodeID() (publ ed25519.PublicKey, priv ed25519.PrivateKey, x []byte, err error) {
	h := sha512.New()
	p := make([]byte, h.Size())
	// Static puzzle
	for {
		publ, priv, err = ed25519.GenerateKey(nil)
		if err != nil {
			return
		}
		h.Reset()
		if _, err = h.Write(publ); err != nil {
			return
		}
		p = h.Sum(p[:0])
		h.Reset()
		if _, err = h.Write(p); err != nil {
			return
		}
		if p = h.Sum(p[:0]); leadingZeros(p) == c1 {
			break
		}
	}
	h = sha3.New512()
	if _, err = h.Write(publ); err != nil {
		return
	}
	p = h.Sum(p[:0])
	x = make([]byte, h.Size())
	p2 := make([]byte, h.Size())
	// Dynamic puzzle
	for {
		if _, err = rand.Read(x); err != nil {
			return
		}
		xor(p2, p, x)
		h.Reset()
		if _, err = h.Write(p2); err != nil {
			return
		}
		if p2 = h.Sum(p2[:0]); leadingZeros(p2) == c2 {
			// Success
			return
		}
	}
}

func VerifyNodeID(publ ed25519.PublicKey, x []byte) bool {
	defer recover()
	if len(publ) != ed25519.PublicKeySize {
		return false
	}
	// Static puzzle
	h := sha512.New()
	if _, err := h.Write(publ); err != nil {
		return false
	}
	p := h.Sum(nil)
	h.Reset()
	if _, err := h.Write(p); err != nil {
		return false
	}
	if p = h.Sum(p[:0]); leadingZeros(p) < c1 {
		return false
	}
	// Dynamic Puzzle
	h = sha3.New512()
	if len(x) != h.Size() {
		return false
	}
	if _, err := h.Write(publ); err != nil {
		return false
	}
	p = h.Sum(p[:0])
	h.Reset()
	xor(p, p, x)
	if _, err := h.Write(p); err != nil {
		return false
	}
	p = h.Sum(p[:0])
	return leadingZeros(p) >= c2
}

// longest common prefix
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