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
)

func main() {
	// Static
	start := time.Now()
	publ, priv, err := Static(8*2, sha512.New())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("publ:", hex.EncodeToString(publ))
	fmt.Println("priv:", hex.EncodeToString(priv))
	fmt.Println("static took:", time.Now().Sub(start))

	// Dynamic from publ
	start = time.Now()
	x, err := Dynamic(8*2, sha512.New(), publ)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("x:", hex.EncodeToString(x))
	fmt.Println("dynamic took:", time.Now().Sub(start))

	// TODO: validation func to check (publ, x) meets c1, c2 requirements
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
	x := make([]byte, ed25519.PublicKeySize)
	buf := make([]byte, ed25519.PublicKeySize)
	var err error
	/*
		publ, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	*/
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
