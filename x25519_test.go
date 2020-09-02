package x25519

import (
	"crypto/ed25519"
	"testing"
)

func TestConvertEd25519(t *testing.T) {
	publ, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	xpubl, err := PublEd25519ToX25519(publ)
	if err != nil {
		t.Fatal(err)
	}
	xpriv, err := PrivEd25519ToX25519(priv)
	if err != nil {
		t.Fatal(err)
	}

	// Check these keys can be used for {en,de}cryption.
	const s = "wowza"
	enc, err := EncryptFixed([]byte(s), xpubl)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptFixed(enc, xpriv)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != s {
		t.Fatalf("want %s, have %s", s, string(dec))
	}
}
