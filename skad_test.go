package main

import (
	"crypto/sha512"
	"testing"

	"golang.org/x/crypto/sha3"
)

const (
	c1 = 8*0 + 6
	c2 = c1
)

func TestCryptoPuzzle(t *testing.T) {
	publ, _, x, err := KeypairFromPuzzles()
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyFromPuzzles(publ, x) {
		t.Fatal("publ invalid")
	}
}

func BenchmarkStatic_SHA512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, _, err := Static(c1, sha512.New()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStatic_SHA3_512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, _, err := Static(c1, sha3.New512()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDynamic_SHA512(b *testing.B) {
	h := sha512.New()
	publ, _, err := Static(c1, h)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = Dynamic(c2, h, publ); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDynamic_SHA3_512(b *testing.B) {
	h := sha3.New512()
	publ, _, err := Static(c1, h)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = Dynamic(c2, h, publ); err != nil {
			b.Fatal(err)
		}
	}
}
