package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type writer struct {
	dst io.Writer

	n      int
	encBuf []byte
	buf    []byte // slice of encBuf
	err    error

	aead cipher.AEAD

	nonce    []byte
	nonceRnd []byte // slice of nonce
	nonceCnt []byte // slice of nonce, sizeof(counter)
	counter  uint64
}

// NewWriter implements encryption for an io.Writer object. Encryption is done
// in chunks of bufsiz plaintext. Writing is buffered, and the object should be
// closed to flush remaining buffered plaintext (by encrypting a smaller last
// chunk). The AEAD nonce is 16 bytes randomly generated followed by an 8-byte
// counter (incrementing for each chunk).
//
// Ciphertext size = len(plaintext) + curve25519.ScalarSize + sha512.Size +
// ((len(plaintext) - 1)/bufsiz + 1) * (chacha20poly1305.NonceSizeX +
// poly1305.TagSize).
func NewWriter(w io.Writer, publ []byte, bufsiz int) (io.WriteCloser, error) {
	if len(publ) != curve25519.ScalarSize {
		return nil, errors.New("bad publ length")
	}
	ePubl, ePriv, err := newX25519Keypair()
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(ePriv, publ)
	if err != nil {
		return nil, err
	}
	// TODO: hkdf-sha512 vs hsalsa20 (from crypto_box)
	salt := make([]byte, sha512.Size)
	if _, err = rand.Read(salt); err != nil {
		return nil, err
	}
	h := hkdf.New(sha512.New, shared, salt, nil)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err = io.ReadFull(h, key); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(ePubl); err != nil {
		return nil, err
	}
	if _, err = w.Write(salt); err != nil {
		return nil, err
	}
	sw := &writer{
		dst:    w,
		encBuf: make([]byte, bufsiz+aead.Overhead()),
		aead:   aead,
		nonce:  make([]byte, aead.NonceSize()),
	}
	sw.buf = sw.encBuf[:bufsiz]
	if len(sw.nonce) < int(unsafe.Sizeof(sw.counter))*2 {
		return nil, errors.New("aead nonce cannot safely hold counter")
	}
	cind := len(sw.nonce) - int(unsafe.Sizeof(sw.counter))
	sw.nonceRnd, sw.nonceCnt = sw.nonce[:cind], sw.nonce[cind:]
	return sw, nil
}

// Write p to the destination with strict buffering.
func (w *writer) Write(p []byte) (n int, err error) {
	// Based on bufio.Writer.Write. Removed large write shortcut to ensure
	// all writes are exactly bufsiz except the last one.
	for len(p) > len(w.buf)-w.n && w.err == nil {
		nn := copy(w.buf[w.n:], p)
		w.n += nn
		w.flush()
		n += nn
		p = p[nn:]
	}
	if w.err != nil {
		return n, w.err
	}
	nn := copy(w.buf[w.n:], p)
	w.n += nn
	n += nn
	return n, nil
}

func (w *writer) flush() {
	if w.n == 0 {
		return
	}
	if _, w.err = rand.Read(w.nonceRnd); w.err != nil {
		return
	}
	binary.BigEndian.PutUint64(w.nonceCnt, w.counter)
	if w.counter == math.MaxUint64 {
		w.err = errors.New("counter overflow, maximum writes exceeded")
		return
	}
	w.counter++
	if _, w.err = w.dst.Write(w.nonce); w.err != nil {
		return
	}
	ciphertext := w.aead.Seal(w.encBuf[:0], w.nonce, w.buf[:w.n], nil)
	w.n = 0
	_, w.err = w.dst.Write(ciphertext)
}

func (w *writer) Close() error {
	if w.err != nil {
		return w.err
	}
	w.flush()
	if w.err != nil {
		return w.err
	}
	w.err = errors.New("writer closed")
	return nil
}

type reader struct {
	src io.Reader

	plain []byte

	// r=read index, w=write index, plain[r:w] is valid
	r, w int

	aead   cipher.AEAD
	cipher []byte
	cn     int

	counter uint64

	err error
}

// NewReader implements decryption for an io.Reader object. Decryption is done
// in chunks of bufsiz plaintext. Reading is buffered, and only reading until
// EOF is gauranteed to result in an empty ciphertext buffer.
func NewReader(r io.Reader, priv []byte, bufsiz int) (io.Reader, error) {
	if len(priv) != curve25519.ScalarSize {
		return nil, errors.New("bad priv length")
	}
	buf := make([]byte, curve25519.ScalarSize+sha512.Size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	ePubl, salt := buf[:curve25519.ScalarSize], buf[curve25519.ScalarSize:]
	shared, err := curve25519.X25519(priv, ePubl)
	if err != nil {
		return nil, err
	}
	h := hkdf.New(sha512.New, shared, salt, nil)
	var key []byte
	// Try to reuse buf
	if len(buf) < chacha20poly1305.KeySize {
		key = make([]byte, chacha20poly1305.KeySize)
	} else {
		key = buf[:chacha20poly1305.KeySize]
	}
	if _, err = io.ReadFull(h, key); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	return &reader{
		src:    r,
		plain:  make([]byte, bufsiz),
		aead:   aead,
		cipher: make([]byte, bufsiz+aead.NonceSize()+aead.Overhead()),
	}, nil
}

func (r *reader) Read(p []byte) (int, error) {
	var n int
	if r.w-r.r > 0 {
		// Copy buffered plaintext
		n += copy(p, r.plain[r.r:r.w])
		p = p[n:]
		r.r += n
	}
	if len(p) == 0 || r.err != nil {
		return n, r.err
	}
	var nn int
	nn, r.err = r.src.Read(r.cipher[r.cn:])
	r.cn += nn
	if r.cn < len(r.cipher) && r.err != io.EOF {
		// Under-read but the stream hasn't ended.
		return n, r.err
	}
	if r.cn < r.aead.NonceSize()+r.aead.Overhead() {
		if r.err == io.EOF {
			r.err = io.ErrUnexpectedEOF
		}
		return n, r.err
	}
	ciphertext := r.cipher[:r.cn]

	nonce := ciphertext[:r.aead.NonceSize()]
	counter := nonce[len(nonce)-8:]
	ciphertext = ciphertext[r.aead.NonceSize():]

	if binary.BigEndian.Uint64(counter) != r.counter {
		r.err = errors.New("invalid nonce counter")
		return n, r.err
	}
	if r.counter == math.MaxUint64 {
		r.err = errors.New("counter overflow, maximum writes exceeded")
		return n, r.err
	}
	r.counter++

	r.plain, r.err = r.aead.Open(r.plain[:0], nonce, ciphertext, nil)
	r.r = 0
	r.w = len(r.plain)
	r.plain = r.plain[:cap(r.plain)]

	// Only the last block may be truncated, set EOF to avoid reading more.
	if r.cn < len(r.cipher) {
		r.err = io.EOF
	}
	r.cn = 0
	nn = copy(p, r.plain[r.r:r.w])
	n += nn
	r.r += nn
	return n, r.err
}
