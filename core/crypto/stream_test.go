package crypto

import (
	"bytes"
	"io"
	"testing"
)

// underReader reads a suboptimal amount n from r (unless n is -1).
type underReader struct {
	r io.Reader
	n int
}

func (ur *underReader) Read(p []byte) (int, error) {
	if ur.n != -1 && len(p) > ur.n {
		return ur.r.Read(p[:ur.n])
	}
	return ur.r.Read(p)
}

func TestStream(t *testing.T) {
	publ, priv, err := newX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	const s = "1234567890"
	bufsizes := []int{
		2,          // under, n%len(s) == 0
		3,          // under, n%len(s) != 0
		len(s),     // exact
		len(s) + 5, // over
	}
	rsizes := []int{
		2,
		3,
		len(s) * 5,
		-1, // No under-reading
	}
	for _, bufsiz := range bufsizes {
		for _, rsiz := range rsizes {
			var b bytes.Buffer
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
			ur := &underReader{&b, rsiz}
			r, err := NewReader(ur, priv, bufsiz)
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
}
