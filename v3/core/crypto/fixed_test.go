package crypto

import "testing"

func TestFixed(t *testing.T) {
	publ, priv, err := newX25519Keypair()
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
		t.Fatalf("want %s, have %s", s, string(dec))
	}
}
