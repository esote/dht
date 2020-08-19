package main

import (
	ed "crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"log"
	"math/bits"

	"golang.org/x/crypto/sha3"
)

type CryptoPuzzle struct {
	c1, c2 int
	h1, h2 hash.Hash
}

func New(c1, c2 int, h1, h2 hash.Hash) (*CryptoPuzzle, error) {
	if c1 == 0 || c1 > 8*h1.Size() {
		return nil, errors.New("c1 invalid")
	}
	if c2 == 0 || c2 > 8*h2.Size() {
		return nil, errors.New("c2 invalid")
	}
	return &CryptoPuzzle{c1, c2, h1, h2}, nil
}

func (c *CryptoPuzzle) Generate() (ed.PublicKey, ed.PrivateKey, []byte, error) {
	publ, priv, err := c.static()
	if err != nil {
		return nil, nil, nil, err
	}
	x, err := c.dynamic(publ)
	if err != nil {
		return nil, nil, nil, err
	}
	return publ, priv, x, nil
}

func (c *CryptoPuzzle) Verify(publ ed.PublicKey, x []byte) bool {
	c.h1.Reset()
	if _, err := c.h1.Write(publ); err != nil {
		return false
	}
	r1 := c.h1.Sum(nil)
	c.h1.Reset()
	if _, err := c.h1.Write(r1); err != nil {
		return false
	}
	r1 = c.h1.Sum(r1[:0])
	if LeadingZeros(r1) != c.c1 {
		return false
	}

	c.h2.Reset()
	if _, err := c.h2.Write(publ); err != nil {
		return false
	}
	r2 := c.h2.Sum(nil)
	if len(x) != len(r2) {
		return false
	}
	Xor(r2, r2, x)
	c.h2.Reset()
	if _, err := c.h2.Write(r2); err != nil {
		return false
	}
	r2 = c.h2.Sum(r2[:0])
	return LeadingZeros(r2) == c.c2
}

func (c *CryptoPuzzle) static() (ed.PublicKey, ed.PrivateKey, error) {
	p := make([]byte, c.h1.Size())
	for {
		publ, priv, err := ed.GenerateKey(nil)
		if err != nil {
			return nil, nil, err
		}
		c.h1.Reset()
		if _, err = c.h1.Write(publ); err != nil {
			return nil, nil, err
		}
		p = c.h1.Sum(p[:0])
		c.h1.Reset()
		if _, err = c.h1.Write(p); err != nil {
			return nil, nil, err
		}
		p = c.h1.Sum(p[:0])
		if LeadingZeros(p) == c.c1 { // TODO: >= c.1 ?
			return publ, priv, nil
		}
	}
}

func (c *CryptoPuzzle) dynamic(publ ed.PublicKey) ([]byte, error) {
	x := make([]byte, c.h2.Size())
	buf := make([]byte, c.h2.Size())
	c.h2.Reset()
	if _, err := c.h2.Write(publ); err != nil {
		return nil, err
	}
	prex := c.h2.Sum(nil)
	p := make([]byte, c.h2.Size())
	for {
		if _, err := cryptorand.Read(x); err != nil {
			return nil, err
		}
		Xor(buf, prex, x)
		c.h2.Reset()
		if _, err := c.h2.Write(buf); err != nil {
			return nil, err
		}
		p := c.h2.Sum(p[:0])
		if LeadingZeros(p) == c.c2 { // TODO: >= c.2 ?
			return x, nil
		}
	}
}

func main() {
	// TODO: best way to chooose c1, c2? increment them until a certain time
	// threshhold?
	const (
		c1 = 8*3 + 0
		c2 = 8*3 + 0
	)
	var (
		h1 = sha512.New()
		h2 = sha3.New512()
	)
	c, err := New(c1, c2, h1, h2)
	if err != nil {
		log.Fatal(err)
	}
	publ, priv, x, err := c.Generate()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("publ:", hex.EncodeToString(publ))
	fmt.Println("priv:", hex.EncodeToString(priv))
	fmt.Println("x:", hex.EncodeToString(x))
	fmt.Println("valid:", c.Verify(publ, x))
}

// Count leading zero bits.
// TODO: assembly impl using SIMD instructions. If len(data) == 32, VPLZCNTQ
// from AVX-512 could check the entire thing in one instruction.
func LeadingZeros(data []byte) int {
	for i := 0; i < len(data); i++ {
		if data[i] != 0 {
			return i*8 + bits.LeadingZeros8(data[i])
		}
	}
	return len(data) * 8
}

// Xor assumes len(a) == len(b) == len(dst)
// TODO: assembly impl using SIMD instructions.
func Xor(dst, a, b []byte) {
	for i := 0; i < len(dst); i++ {
		dst[i] = a[i] ^ b[i]
	}
}
