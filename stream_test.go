package x25519

import (
	"bytes"
	"io"
	"testing"
)

func TestStream(t *testing.T) {
	var b bytes.Buffer
	publ, priv, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	const s = "1234567890"
	sizes := []int{
		2,      // under n%len(s) == 0
		3,      // under, n%len(s) != 0
		len(s), // exact
		15,     // over
	}
	for _, bufsiz := range sizes {
		wc, err := NewWriter(&b, publ, bufsiz)
		if err != nil {
			t.Fatal(err)
		}
		n, err := wc.Write([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		if n != len(s) {
			t.Fatalf("want %d, have %d bytes written", len(s), n)
		}
		if err = wc.Close(); err != nil {
			t.Fatal(err)
		}
		r, err := NewReader(&b, priv, bufsiz)
		if err != nil {
			t.Fatal(err)
		}
		plain := make([]byte, len(s))
		n, err = io.ReadFull(r, plain)
		if err != nil {
			t.Fatal(err)
		}
		if n != len(s) {
			t.Fatalf("want %d, have %d bytes read", len(s), n)
		}
		if string(plain) != s {
			t.Fatalf("want %s, have %s", s, string(plain))
		}
	}
}
