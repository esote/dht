// Package crypto provides tools for encrypting and decrypting data in fixed and
// stream formats, and for converting Ed25519 keys to X25519 keys.
//
// Encryption for a target X25519 public key is done as follows. Generate an
// ephemeral X25519 keypair and compute a shared secret between the ephemeral
// private key and the target public key. This shared secret is passed to a
// SHA-512 HKDF with a random salt. From this HKDF, read a 32-byte key. The
// HKDF-read key is passed as the key to an XChaCha20-Poly1305 AEAD (ChaCha20
// with extendend nonce and Poly1305 MACs). Finally a 24-byte nonce must be
// passed with the plaintext to the AEAD, which produces the ciphertext.
package crypto
