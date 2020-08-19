package main

import (
	"crypto/sha512"
	"hash"
	"testing"

	"golang.org/x/crypto/sha3"
)

const (
	c1 = 8*0 + 6
	c2 = c1
)

func TestCryptoPuzzle(t *testing.T) {
	c, err := New(c1, c2, sha512.New(), sha512.New())
	if err != nil {
		t.Fatal(err)
	}
	publ, _, x, err := c.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !c.Verify(publ, x) {
		t.Fatal("publ invalid")
	}
}

func BenchmarkStatic(b *testing.B) {
	b.Run("sha512", func(b *testing.B) {
		benchmarkStatic(b, sha512.New())
	})
	b.Run("sha3-512", func(b *testing.B) {
		benchmarkStatic(b, sha3.New512())
	})
}

func BenchmarkDynamic(b *testing.B) {
	b.Run("sha512", func(b *testing.B) {
		benchmarkDynamic(b, sha512.New())
	})
	b.Run("sha3-512", func(b *testing.B) {
		benchmarkDynamic(b, sha3.New512())
	})
}

func benchmarkStatic(b *testing.B, h hash.Hash) {
	c, err := New(c1, c2, h, h)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err = c.static(); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkDynamic(b *testing.B, h hash.Hash) {
	c, err := New(c1, c2, h, h)
	if err != nil {
		b.Fatal(err)
	}
	publ, _, err := c.static()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = c.dynamic(publ); err != nil {
			b.Fatal(err)
		}
	}
}
