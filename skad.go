package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"log"
	"math/bits"
	"time"

	"golang.org/x/crypto/sha3"
)

func main() {
	// Static
	const c1 = 8 * 1
	start := time.Now()
	publ, priv, err := Static(c1, sha512.New())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("publ:", hex.EncodeToString(publ))
	fmt.Println("priv:", hex.EncodeToString(priv))
	fmt.Println("static took:", time.Now().Sub(start))

	// Dynamic from publ
	const c2 = c1
	start = time.Now()
	x, err := Dynamic(c2, sha512.New(), publ)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("x:", hex.EncodeToString(x))
	fmt.Println("dynamic took:", time.Now().Sub(start))

	// TODO: validation func to check (publ, x) meets c1, c2 requirements
	fmt.Println("valid:", Verify(c1, c2, sha512.New(), sha512.New(), publ, x))
}

// TODO: define struct to keep c1, c2, h1, h2 for gen and verif
// TODO: best way to chooose c1, c2? increment them until a certain time thresh?
// Use sha512 for static and sha3-512 for dynamic for diversify hashes used.
func KeypairFromPuzzles() (ed25519.PublicKey, ed25519.PrivateKey, []byte, error) {
	publ, priv, err := Static(8*2, sha512.New())
	if err != nil {
		return nil, nil, nil, err
	}
	x, err := Dynamic(8*2, sha3.New512(), publ)
	if err != nil {
		return nil, nil, nil, err
	}
	return publ, priv, x, nil
}

// Verify public key chosen from KeypairFromPuzzles
func VerifyFromPuzzles(publ ed25519.PublicKey, x []byte) bool {
	return Verify(8*2, 8*2, sha512.New(), sha3.New512(), publ, x)
}

func Verify(c1, c2 int, h1, h2 hash.Hash, publ ed25519.PublicKey, x []byte) bool {
	h1.Reset()
	if _, err := h1.Write(publ); err != nil {
		return false
	}
	r1 := h1.Sum(nil)
	h1.Reset()
	if _, err := h1.Write(r1); err != nil {
		return false
	}
	r1 = h1.Sum(r1[:0])
	if LeadingZeros(r1) != c1 {
		return false
	}

	h2.Reset()
	if _, err := h2.Write(publ); err != nil {
		return false
	}
	r2 := h2.Sum(nil)
	if len(x) != len(r2) {
		return false
	}
	Xor(r2, r2, x)
	h2.Reset()
	if _, err := h2.Write(r2); err != nil {
		return false
	}
	r2 = h2.Sum(r2[:0])
	return LeadingZeros(r2) == c2
}

func Static(c1 int, h hash.Hash) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if c1 == 0 || c1 > 8*ed25519.PublicKeySize {
		return nil, nil, errors.New("c1 invalid")
	}
	// Allocate p early to reuse it.
	p := make([]byte, h.Size())
	for {
		publ, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		h.Reset()
		if _, err = h.Write(publ); err != nil {
			return nil, nil, err
		}
		p = h.Sum(p[:0])
		h.Reset()
		if _, err = h.Write(p); err != nil {
			return nil, nil, err
		}
		p = h.Sum(p[:0])
		if LeadingZeros(p) == c1 {
			return publ, priv, nil
		}
	}
}

func Dynamic(c2 int, h hash.Hash, publ ed25519.PublicKey) ([]byte, error) {
	if c2 == 0 || c2 > 8*ed25519.PublicKeySize {
		return nil, errors.New("c2 invalid")
	}
	x := make([]byte, h.Size())
	buf := make([]byte, h.Size())
	var err error
	h.Reset()
	if _, err = h.Write(publ); err != nil {
		return nil, err
	}
	prex := h.Sum(nil)
	// Allocate p early to reuse it.
	p := make([]byte, h.Size())
	for {
		if _, err = rand.Read(x); err != nil {
			return nil, err
		}
		Xor(buf, prex, x)
		h.Reset()
		if _, err = h.Write(buf); err != nil {
			return nil, err
		}
		p := h.Sum(p[:0])
		if LeadingZeros(p) == c2 {
			return x, nil
		}
	}
}

// TODO: assembly impl?
func LeadingZeros(data []byte) int {
	for i := 0; i < len(data); i++ {
		if data[i] != 0 {
			return i*8 + bits.LeadingZeros8(data[i])
		}
	}
	return len(data) * 8
}

// Xor assumes len(a) == len(b) == len(dst)
func Xor(dst, a, b []byte) {
	for i := 0; i < len(dst); i++ {
		dst[i] = a[i] ^ b[i]
	}
}
