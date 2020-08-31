package main

import (
	"testing"
)

func Test(t *testing.T) {
	publ, priv, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	const s = "hello"
	enc, err := EncryptFixed([]byte(s), publ)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptFixed(enc, priv)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != s {
		t.Fatal("dec(enc(s)) != s")
	}
}
