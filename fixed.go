package x25519

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"
)

const (
	nonceSize    = chacha20poly1305.NonceSizeX
	overheadSize = poly1305.TagSize
)

func FixedLength(l int) int {
	return l + curve25519.ScalarSize + sha512.Size + nonceSize +
		overheadSize
}

func EncryptFixed(plaintext, publ []byte) ([]byte, error) {
	if len(publ) != curve25519.ScalarSize {
		return nil, errors.New("bad publ length")
	}
	ePubl, ePriv, err := NewKeypair()
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

	// out = ephemeral public key || hkdf salt || nonce || ciphertext
	l := len(ePubl) + len(salt) + aead.NonceSize() + len(plaintext) +
		aead.Overhead()
	out := make([]byte, l)
	var off int

	copy(out, ePubl)
	off += len(ePubl)

	copy(out[off:], salt)
	off += len(salt)

	nonce := out[off : off+aead.NonceSize()]
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	off += len(nonce)

	return aead.Seal(out[:off], nonce, plaintext, nil), nil
}

func DecryptFixed(ciphertext, priv []byte) ([]byte, error) {
	if len(priv) != curve25519.ScalarSize {
		return nil, errors.New("bad priv length")
	}
	if len(ciphertext) < curve25519.ScalarSize {
		return nil, errors.New("ciphertext has no ephemeral public key")
	}
	ePubl := ciphertext[:curve25519.ScalarSize]
	ciphertext = ciphertext[curve25519.ScalarSize:]
	shared, err := curve25519.X25519(priv, ePubl)
	if err != nil {
		return nil, err
	}
	salt := ciphertext[:sha512.Size]
	ciphertext = ciphertext[sha512.Size:]
	h := hkdf.New(sha512.New, shared, salt, nil)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err = io.ReadFull(h, key); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	// TODO: len(ciphertext) enough for nonce
	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]
	out := make([]byte, len(ciphertext)-aead.Overhead())
	return aead.Open(out[:0], nonce, ciphertext, nil)
}
