package x25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"math/big"

	"golang.org/x/crypto/curve25519"
)

func NewKeypair() ([]byte, []byte, error) {
	priv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(priv); err != nil {
		return nil, nil, err
	}
	publ, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return publ, priv, nil
}

// Prime p 2^255 - 19
//
// Source: Curve25519: new Diffie-Hellman speed records
// https://cr.yp.to/ecdh/curve25519-20060209.pdf.
var curve25519P, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)

// Convert an Ed25519 public key to a X25519 key. Converts the y-coordinate
// of a twisted Edwards curve to the u-coordinate of a Montgomery curve.
//
// The Ed25519 public key is assumed to be encoded according to RFC 8032, as
// used in golang.org/crypto/ed25519.
//
// TODO: compare to libsodium, ensure we get the same results
// TODO: libsodium does various checks on the public key prior to converting
func PublEd25519ToX25519(publ ed25519.PublicKey) []byte {
	if len(publ) != ed25519.PublicKeySize {
		panic("bad ed25519 public key length")
	}

	// publ is little endian, SetBytes takes big endian
	Y := make([]byte, ed25519.PublicKeySize)
	swapEndian(Y, publ)

	// Clear sign bit from x-coodinate (RFC 8032, section 3.1).
	Y[0] &= 0b0111_111

	/*
		u = (1 + y) / (1 - y)

		Source: Twisted Edwards Curves, Theorem 3.2
		https://eprint.iacr.org/2008/013.pdf

		Mod{Inverse} to keep within the prime field.
	*/
	y := new(big.Int).SetBytes(Y)
	denom := big.NewInt(1)
	denom.ModInverse(denom.Sub(denom, y), curve25519P) // 1 / (1 - y)
	u := y.Mul(y.Add(y, big.NewInt(1)), denom)         // (y + 1) * denom
	u.Mod(u, curve25519P)

	// u is big endian, convert to little endian.
	U := make([]byte, curve25519.PointSize)
	ub := u.Bytes()
	if len(ub) > curve25519.PointSize {
		panic("u coordinate not constrainted to prime field")
	}
	swapEndian(U, ub)
	return U
}

// Swap endianness of src into dst, assumes len(dst) >= len(src).
func swapEndian(dst, src []byte) {
	for i, b := range src {
		dst[len(src)-i-1] = b
	}
}
