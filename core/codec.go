package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
	"math"
	"time"

	"github.com/esote/dht/core/crypto"
	"golang.org/x/crypto/sha3"
)

// MessageCodec implements encryption and decryption of fixed and stream-format
// messages. It is safe for concurrent use.
type MessageCodec struct {
	c1, c2 int
}

// NewMessageCodec constructs a MessageCodec with the c1 static puzzle constant
// and c2 dynamic puzzle constant. A given codec M is compatible with another
// codec N if M.C1 >= N.C1 and M.C2 >= N.C2.
func NewMessageCodec(c1, c2 int) *MessageCodec {
	return &MessageCodec{c1, c2}
}

// NewNodeID generates a keypair where the public key (node ID) satisfies the
// codec's crypto puzzle constants and may be used in codec operations.
func (codec *MessageCodec) NewNodeID() (publ ed25519.PublicKey, priv ed25519.PrivateKey, x []byte, err error) {
	// Static puzzle
	h := sha512.New()
	p := make([]byte, h.Size())
	for {
		publ, priv, err = ed25519.GenerateKey(nil)
		if err != nil {
			return
		}
		h.Reset()
		if _, err = h.Write(publ); err != nil {
			return
		}
		p = h.Sum(p[:0])
		h.Reset()
		if _, err = h.Write(p); err != nil {
			return
		}
		if p = h.Sum(p[:0]); leadingZeros(p) >= codec.c1 {
			// Success
			break
		}
	}

	// Dynamic puzzle
	h = sha3.New512()
	if _, err = h.Write(publ); err != nil {
		return
	}
	p = h.Sum(p[:0])
	x = make([]byte, h.Size())
	p2 := make([]byte, h.Size())
	for {
		if _, err = rand.Read(x); err != nil {
			return
		}
		xor(p2, p, x)
		h.Reset()
		if _, err = h.Write(p2); err != nil {
			return
		}
		if p2 = h.Sum(p2[:0]); leadingZeros(p2) >= codec.c2 {
			// Success
			return
		}
	}
}

// verifyNodeID checks that a public key (node ID) satisfies the crypto puzzle
// constraints c1 and c2.
func (codec *MessageCodec) verifyNodeID(publ ed25519.PublicKey, x []byte) bool {
	defer func() {
		_ = recover()
	}()

	// Static puzzle
	if len(publ) != ed25519.PublicKeySize {
		return false
	}
	h := sha512.New()
	if _, err := h.Write(publ); err != nil {
		return false
	}
	p := h.Sum(nil)
	h.Reset()
	if _, err := h.Write(p); err != nil {
		return false
	}
	if p = h.Sum(p[:0]); leadingZeros(p) < codec.c1 {
		return false
	}

	// Dynamic Puzzle
	h = sha3.New512()
	if len(x) != h.Size() {
		return false
	}
	if _, err := h.Write(publ); err != nil {
		return false
	}
	p = h.Sum(p[:0])
	h.Reset()
	xor(p, p, x)
	if _, err := h.Write(p); err != nil {
		return false
	}
	p = h.Sum(p[:0])
	return leadingZeros(p) >= codec.c2
}

// EncodeFixed returns the fixed-format encoding of msg.
func (codec *MessageCodec) EncodeFixed(msg *Message, priv, targetPubl []byte) ([]byte, error) {
	data := make([]byte, FixedMessageSize)
	b := data

	if _, ok := SupportedVersions[msg.Version]; !ok {
		return nil, errors.New("unsupported version")
	}
	b[0] = msg.Version
	b = b[1:]

	switch msg.BodyKind {
	case KindFixed:
	default:
		return nil, errors.New("unsupported body kind")
	}
	b[0] = msg.BodyKind
	b = b[1:]

	header, err := msg.Hdr.MarshalBinary()
	if err != nil {
		return nil, err
	}

	fixed, ok := msg.Payload.(FixedPayload)
	if !ok {
		return nil, errors.New("payload type invalid")
	}
	payload, err := fixed.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Zero-padding is implicit in uninitialized buffer space.
	plain := make([]byte, FixedCipherSize-SigSize, FixedCipherSize)
	b = plain

	copy(b, header)
	b = b[len(header):]

	copy(b, payload)
	b = b[len(payload):]

	// Sign (header || payload || padding)
	sig := ed25519.Sign(priv, plain)
	plain = append(plain, sig...)

	xpubl, err := crypto.PublEd25519ToX25519(targetPubl)
	if err != nil {
		return nil, err
	}

	ciphertext, err := crypto.EncryptFixed(plain, xpubl)
	if err != nil {
		return nil, err
	}

	if len(data)-PreBodySize != len(ciphertext) {
		return nil, errors.New("ciphertext positioning invalid")
	}
	copy(data[PreBodySize:], ciphertext)

	return data, nil
}

// DecodeFixed decodes data to a fixed-format msg.
func (codec *MessageCodec) DecodeFixed(msg *Message, data, priv []byte) error {
	if len(data) < FixedMessageSize {
		return errors.New("message truncated")
	}

	msg.Version = data[0]
	data = data[1:]

	if _, ok := SupportedVersions[msg.Version]; !ok {
		return errors.New("unsupported version")
	}

	msg.BodyKind = data[0]
	data = data[1:]

	switch msg.BodyKind {
	case KindFixed:
	default:
		return errors.New("body kind invalid")
	}

	xpriv, err := crypto.PrivEd25519ToX25519(priv)
	if err != nil {
		return err
	}

	plain, err := crypto.DecryptFixed(data, xpriv)
	if err != nil {
		return err
	}

	if len(plain) < SigSize {
		return errors.New("plaintext body truncated")
	}
	plain, sig := plain[:len(plain)-SigSize], plain[len(plain)-SigSize:]

	msg.Hdr = new(Header)
	if err = msg.Hdr.UnmarshalBinary(plain); err != nil {
		return err
	}
	if err = codec.verifyHeader(msg.Hdr); err != nil {
		return err
	}
	if !ed25519.Verify(msg.Hdr.ID, plain, sig) {
		return errors.New("signature invalid")
	}
	plain = plain[HeaderSize:]

	switch msg.Hdr.MsgType {
	case TypePing:
		msg.Payload = new(PingPayload)
	case TypeStore:
		msg.Payload = new(StorePayload)
	case TypeFindNode:
		msg.Payload = new(FindNodePayload)
	case TypeFindNodeResp:
		msg.Payload = new(FindNodeRespPayload)
	case TypeFindValue:
		msg.Payload = new(FindValuePayload)
	case TypeError:
		msg.Payload = new(ErrorPayload)
	default:
		return errors.New("message type unsupported")
	}
	payload, ok := msg.Payload.(FixedPayload)
	if !ok {
		return errors.New("payload type not fixed")
	}
	n, err := payload.UnmarshalBinaryN(plain)
	if err != nil {
		return err
	}
	plain = plain[n:]

	for i := range plain {
		if plain[i] != 0 {
			return errors.New("padding invalid")
		}
	}

	return nil
}

// EncodeStream writes the stream-format encoding of msg to w.
func (codec *MessageCodec) EncodeStream(msg *Message, w io.Writer, priv, targetPubl []byte) error {
	data := make([]byte, PreBodySize)
	b := data

	if _, ok := SupportedVersions[msg.Version]; !ok {
		return errors.New("unsupported version")
	}
	b[0] = msg.Version
	b = b[1:]

	switch msg.BodyKind {
	case KindStream:
	default:
		return errors.New("unsupported body kind")
	}
	b[0] = msg.BodyKind
	b = b[1:]

	if _, err := w.Write(data); err != nil {
		return err
	}

	xpubl, err := crypto.PublEd25519ToX25519(targetPubl)
	if err != nil {
		return err
	}

	wc, err := crypto.NewWriter(w, xpubl, StreamCipherBlockSize)
	if err != nil {
		return err
	}

	header, err := msg.Hdr.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err = wc.Write(header); err != nil {
		return err
	}

	sig := ed25519.Sign(priv, header)
	if _, err = wc.Write(sig); err != nil {
		return err
	}

	stream, ok := msg.Payload.(StreamPayload)
	if !ok {
		return errors.New("payload type invalid")
	}
	if err = stream.MarshalStream(wc); err != nil {
		return err
	}

	return wc.Close()
}

// DecodeStream decodes from stream-format r to msg.
func (codec *MessageCodec) DecodeStream(msg *Message, r io.Reader, priv []byte) error {
	data := make([]byte, PreBodySize)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}

	msg.Version = data[0]
	data = data[1:]

	if _, ok := SupportedVersions[msg.Version]; !ok {
		return errors.New("unsupported version")
	}

	msg.BodyKind = data[0]
	data = data[1:]

	switch msg.BodyKind {
	case KindStream:
	default:
		return errors.New("body kind invalid")
	}

	xpriv, err := crypto.PrivEd25519ToX25519(priv)
	if err != nil {
		return err
	}

	r, err = crypto.NewReader(r, xpriv, StreamCipherBlockSize)
	if err != nil {
		return err
	}

	data = make([]byte, HeaderSize+SigSize)
	if _, err = io.ReadFull(r, data); err != nil {
		return err
	}
	header, sig := data[:HeaderSize], data[HeaderSize:]
	msg.Hdr = new(Header)
	if err = msg.Hdr.UnmarshalBinary(header); err != nil {
		return err
	}
	if err = codec.verifyHeader(msg.Hdr); err != nil {
		return err
	}
	if !ed25519.Verify(msg.Hdr.ID, header, sig) {
		return errors.New("signature invalid")
	}

	switch msg.Hdr.MsgType {
	case TypeData:
		msg.Payload = new(DataPayload)
	default:
		return errors.New("message type unsupported")
	}
	stream, ok := msg.Payload.(StreamPayload)
	if !ok {
		return errors.New("payload type not stream")
	}
	if err = stream.UnmarshalStream(r); err != nil {
		return err
	}

	return nil
}

func (codec *MessageCodec) verifyHeader(hdr *Header) error {
	if hdr.Time > uint64(math.MaxInt64) {
		return errors.New("header time too large")
	}
	if time.Unix(int64(hdr.Time), 0).Before(time.Now().UTC()) {
		return errors.New("header expired")
	}
	if !codec.verifyNodeID(hdr.ID, hdr.PuzDynX) {
		return errors.New("node ID invalid")
	}
	return nil
}
