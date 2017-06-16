package noise

import (
	"bytes"
	"errors"
	"math"
	"strings"
)

//
// CipherState object
//

type cipherState struct {
	k [32]byte
	n uint64
}

func (c *cipherState) initializeKey(key []byte) {
	copy(c.k[:], key)
	c.n = 0
}

func (c cipherState) hasKey() bool {

	for _, ki := range c.k {
		// Returns true if k is non-empty
		if ki != 0 {
			return true
		}
	}

	return false
}

func (c *cipherState) encryptWithAd(ad, plaintext []byte) (ciphertext []byte, err error) {

	//  If incrementing n results in 2^64-1, then any further encryptWithAd() call will signal an error to the caller
	if c.n == math.MaxUint64 {
		err = errors.New("nonce has reached maximum size")
		return
	}

	// If k is non-empty returns encrypt(k, n++, ad, plaintext).
	if c.hasKey() {
		ciphertext = encrypt(c.k, c.n, ad, plaintext)
		c.n++
		return
	}

	// Otherwise returns plaintext.
	ciphertext = plaintext

	return
}

func (c *cipherState) decryptWithAd(ad, ciphertext []byte) (plaintext []byte, err error) {

	//  If incrementing n results in 2^64-1, then any further decryptWithAd() call will signal an error to the caller
	if c.n == math.MaxUint64 {
		err = errors.New("nonce has reached maximum size")
		return
	}

	// If k is non-empty returns decrypt(k, n++, ad, ciphertext).
	if c.hasKey() {
		plaintext, err = decrypt(c.k, c.n, ad, ciphertext)

		// If an authentication failure occurs in decrypt() then n is not incremented and an error is signaled to the caller.
		if err != nil {
			return
		}

		c.n++

		return
	}

	// Otherwise returns ciphertext.
	plaintext = ciphertext

	return
}

func (c *cipherState) rekey() {
	c.k = rekey(c.k)
}

//
// SymmetricState object
//

type symmetricState struct {
	cipherState cipherState
	ck          [hashLen]byte
	h           [hashLen]byte
}

func (s *symmetricState) initializeSymmetric(protocolName []byte) {
	if pad := hashLen - len(protocolName); pad >= 0 {
		// If protocolName is less than or equal to hashLen bytes in length,
		// sets h equal to protocolName with zero bytes appended to make hashLen bytes.
		copy(s.h[:], append(protocolName, bytes.Repeat([]byte{0}, pad)...))
	} else {
		// Otherwise sets h = hash(protocolName).
		s.h = hash(protocolName)
	}

	s.ck = s.h

	//	initializeKey() // This is done by default in Go
}

func (s *symmetricState) mixKey(inputKeyMaterial [32]byte) {

	output := hkdf(s.ck[:], inputKeyMaterial[:], 2)
	copy(s.ck[:], output[:hashLen])

	// The output of HKDF is taken as is because we use hashLen = 32
	s.cipherState.initializeKey(output[hashLen:])

}

func (s *symmetricState) mixHash(data []byte) {
	s.h = hash(append(s.h[:], data...))
}

func (s *symmetricState) mixKeyAndHash(inputKeyMaterial []byte) {

	output := hkdf(s.ck[:], inputKeyMaterial, 3)

	copy(s.ck[:], output[:hashLen])

	s.mixHash(output[hashLen : hashLen*2])

	// The output of HKDF is taken as is because we use hashLen = 32

	s.cipherState.initializeKey(output[hashLen*2:])
}

// encrypts the plaintext and authenticates the hash
// then insert the ciphertext in the running hash
func (s *symmetricState) encryptAndHash(plaintext []byte) (ciphertext []byte) {

	// Note that if k is empty, the encryptWithAd() call will set ciphertext equal to plaintext.
	ciphertext, err := s.cipherState.encryptWithAd(s.h[:], plaintext)

	// TODO: this should probably kill the session instead (nonce reached maximum size)
	if err != nil {
		panic(err)
	}

	s.mixHash(ciphertext)

	return
}

// decrypts the ciphertext and authenticates the hash
func (s *symmetricState) decryptAndHash(ciphertext []byte) (plaintext []byte) {

	// Note that if k is empty, the decryptWithAd() call will set plaintext equal to ciphertext.
	plaintext, err := s.cipherState.decryptWithAd(s.h[:], ciphertext)

	// TODO: handle this gracefuly! Could be nonce problem or mac problem
	if err != nil {
		panic(err)
	}

	s.mixHash(ciphertext)

	return
}

func (s symmetricState) Split() (c1 cipherState, c2 cipherState) {

	output := hkdf(s.ck[:], []byte{}, 2)

	// The output of HKDF is taken as is because we use hashLen = 32

	c1.initializeKey(output[:hashLen])
	c2.initializeKey(output[hashLen:])

	return
}

//
// Handshake Patterns
//

type handshakePattern struct {
	initiatorPreMessagePattern string
	responderPreMessagePattern string
	messagePattern             []string
}

var patterns = map[string]handshakePattern{
	"XX": handshakePattern{
		"",
		"",
		[]string{"->e", "<-e, ee, s, es", "->s, se"},
	},
}

//
// HandshakeState object
//

type handshakeState struct {
	symmetricState symmetricState
	/* Empty is a special value which indicates the variable has not yet been initialized.
	we'll use keyPair.privateKey = 0 as Empty
	*/
	s  keyPair // The local static key pair
	e  keyPair // The local ephemeral key pair
	rs keyPair // The remote party's static public key
	re keyPair // The remote party's ephemeral public key

	initiator      bool     // A boolean indicating the initiator or responder role.
	messagePattern []string // A sequence of message patterns. Each message pattern is a sequence of tokens from the set ("e", "s", "ee", "es", "se", "ss")
}

var EmptyKey = keyPair{}

func Initialize(handshakePattern string, initiator bool, prologue []byte, s, e, rs, re *keyPair) (h handshakeState) {
	if _, ok := patterns[handshakePattern]; !ok {
		panic("the supplied handshakePattern does not exist")
	}

	h.symmetricState.initializeSymmetric([]byte("Noise_" + handshakePattern + "_25519_ChaChaPoly_SHA256"))

	h.symmetricState.mixHash(prologue)

	if s != nil {
		h.s = *s
	}
	if e != nil {
		h.e = *e
	}
	if rs != nil {
		h.rs = *rs
	}
	if re != nil {
		h.re = *re
	}
	h.initiator = initiator

	//Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern, with the specified public key as input (see Section 7 for an explanation of pre-messages). If both initiator and responder have pre-messages, the initiator's public keys are hashed first.

	// TODO: understand "e" in pre-message patterns
	if strings.Contains(patterns[handshakePattern].initiatorPreMessagePattern, "s") {
		h.symmetricState.mixHash(s.publicKey[:])
	}
	if strings.Contains(patterns[handshakePattern].responderPreMessagePattern, "s") {
		h.symmetricState.mixHash(rs.publicKey[:])
	}

	h.messagePattern = patterns[handshakePattern].messagePattern

	return
}

func (h *handshakeState) WriteMessage(payload []byte, messageBuffer *[]byte) (c1 cipherState, c2 cipherState) {
	// example: h.messagePattern[0] = "->e,se,ss"
	if len(h.messagePattern) == 0 {
		panic("no more message pattern to write")
	}
	patterns := strings.Split(h.messagePattern[0][2:], ",")

	// process the patterns
	for _, pattern := range patterns {

		pattern = strings.Trim(pattern, " ")

		if pattern == "e" {
			h.e = GenerateKeypair()
			*messageBuffer = append(*messageBuffer, h.e.publicKey[:]...)
			h.symmetricState.mixHash(h.e.publicKey[:])
		} else if pattern == "s" {
			*messageBuffer = append(*messageBuffer, h.symmetricState.encryptAndHash(h.s.publicKey[:])...)
		} else if pattern == "ee" {
			h.symmetricState.mixKey(dh(h.e, h.re.publicKey))
		} else if pattern == "es" {
			if h.initiator {
				h.symmetricState.mixKey(dh(h.e, h.rs.publicKey))
			} else {
				h.symmetricState.mixKey(dh(h.s, h.re.publicKey))
			}
		} else if pattern == "se" {
			if h.initiator {
				h.symmetricState.mixKey(dh(h.s, h.re.publicKey))
			} else {
				h.symmetricState.mixKey(dh(h.e, h.rs.publicKey))
			}
		} else if pattern == "ss" {
			h.symmetricState.mixKey(dh(h.s, h.rs.publicKey))
		} else {
			panic("pattern not allowed")
		}
	}

	// Appends EncryptAndHash(payload) to the buffer
	*messageBuffer = append(*messageBuffer, h.symmetricState.encryptAndHash(payload)...)

	// remove the pattern from the messagePattern
	if len(h.messagePattern) == 1 {
		// If there are no more message patterns returns two new CipherState objects
		h.messagePattern = nil
		c1, c2 = h.symmetricState.Split()
	} else {
		h.messagePattern = h.messagePattern[1:]
	}
	return
}

func (h *handshakeState) ReadMessage(message []byte, payloadBuffer *[]byte) (c1 cipherState, c2 cipherState) {
	// example: h.messagePattern[0] = "->e,se,ss"
	if len(h.messagePattern) == 0 {
		panic("no more message pattern to read")
	}
	patterns := strings.Split(h.messagePattern[0][2:], ",")

	// process the patterns
	offset := 0

	for _, pattern := range patterns {

		pattern = strings.Trim(pattern, " ")

		if pattern == "e" {
			copy(h.re.publicKey[:], message[offset:offset+dhLen])
			offset += dhLen
			h.symmetricState.mixHash(h.re.publicKey[:])
		} else if pattern == "s" {
			tagLen := 0
			if h.symmetricState.cipherState.hasKey() {
				tagLen = 16
			}

			copy(h.rs.publicKey[:], h.symmetricState.decryptAndHash(message[offset:offset+dhLen+tagLen]))
			offset += dhLen + tagLen
		} else if pattern == "ee" {
			h.symmetricState.mixKey(dh(h.e, h.re.publicKey))
		} else if pattern == "es" {
			if h.initiator {
				h.symmetricState.mixKey(dh(h.e, h.rs.publicKey))
			} else {
				h.symmetricState.mixKey(dh(h.s, h.re.publicKey))
			}
		} else if pattern == "se" {
			if h.initiator {
				h.symmetricState.mixKey(dh(h.s, h.re.publicKey))
			} else {
				h.symmetricState.mixKey(dh(h.e, h.rs.publicKey))
			}
		} else if pattern == "ss" {
			h.symmetricState.mixKey(dh(h.s, h.rs.publicKey))
		} else {
			panic("pattern not allowed")
		}
	}

	// Appends EncryptAndHash(payload) to the buffer
	*payloadBuffer = append(*payloadBuffer, h.symmetricState.decryptAndHash(message[offset:])...)

	// remove the pattern from the messagePattern
	if len(h.messagePattern) == 1 {
		// If there are no more message patterns returns two new CipherState objects
		h.messagePattern = nil
		c1, c2 = h.symmetricState.Split()
	} else {
		h.messagePattern = h.messagePattern[1:]
	}
	return
}
