/*
 * This is a readable implementation of Noise_XX_25519_ChaChaPoly_SHA256
 * from the Noise Protocol Framework.
 *
 * Warning: it hasn't been fully tested
 *
 * There is probably no point extending this library with more patterns, although it is possible.
 *
 * Author: David Wong
 */

package noise

import (
	"bytes"
	"errors"
	"math"
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

// TODO: add documentation for public functions, also test this function
func (c *cipherState) Rekey() {
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
func (s *symmetricState) encryptAndHash(plaintext []byte) (ciphertext []byte, err error) {

	// Note that if k is empty, the encryptWithAd() call will set ciphertext equal to plaintext.
	ciphertext, err = s.cipherState.encryptWithAd(s.h[:], plaintext)

	if err != nil {
		return
	}

	s.mixHash(ciphertext)

	return
}

// decrypts the ciphertext and authenticates the hash
func (s *symmetricState) decryptAndHash(ciphertext []byte) (plaintext []byte, err error) {

	// Note that if k is empty, the decryptWithAd() call will set plaintext equal to ciphertext.
	plaintext, err = s.cipherState.decryptWithAd(s.h[:], ciphertext)

	if err != nil {
		return
	}

	s.mixHash(ciphertext)

	return
}

func (s symmetricState) Split() (c1, c2 *cipherState) {
	c1 = new(cipherState)
	c2 = new(cipherState)
	output := hkdf(s.ck[:], []byte{}, 2)
	// The output of HKDF is taken as is because we use hashLen = 32
	c1.initializeKey(output[:hashLen])
	c2.initializeKey(output[hashLen:])
	return
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

	initiator       bool             // A boolean indicating the initiator or responder role.
	messagePatterns []messagePattern // A sequence of message patterns. Each message pattern is a sequence of tokens from the set ("e", "s", "ee", "es", "se", "ss")

	shouldWrite bool // A boolean indicating if the role of the peer is to WriteMessage or ReadMessage
}

// This allows you to initialize a peer.
// * see `patterns` for a list of available handshakePatterns
// * initiator = false means the instance is for a responder
// * prologue is a byte string record of anything that happened prior the Noise handshakeState
// * s, e, rs, re are the local and remote static/ephemeral key pairs to be set (if they exist)
// the function returns a handshakeState object.
func Initialize(handshakeType noiseHandshakeType, initiator bool, prologue []byte, s, e, rs, re *keyPair) (h handshakeState) {

	handshakePattern, ok := patterns[handshakeType]
	if !ok {
		panic("Noise: the supplied handshakePattern does not exist")
	}

	h.symmetricState.initializeSymmetric([]byte("Noise_" + handshakePattern.name + "_25519_ChaChaPoly_SHA256"))

	h.symmetricState.mixHash(prologue)

	if s != nil {
		h.s = *s
	}
	if e != nil {
		panic("Noise: fallback patterns are not implemented")
	}
	if rs != nil {
		h.rs = *rs
	}
	if re != nil {
		panic("Noise: fallback patterns are not implemented")
	}

	h.initiator = initiator
	h.shouldWrite = initiator

	//Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern, with the specified public key as input (see Section 7 for an explanation of pre-messages). If both initiator and responder have pre-messages, the initiator's public keys are hashed first.

	// initiator pre-message pattern
	for _, token := range handshakePattern.preMessagePatterns[0] {
		if token == token_s {
			if initiator {
				h.symmetricState.mixHash(s.publicKey[:])
			} else {
				h.symmetricState.mixHash(rs.publicKey[:])
			}
		} else {
			panic("Noise: token of pre-message not supported")
		}
	}

	// responder pre-message pattern
	for _, token := range handshakePattern.preMessagePatterns[1] {
		if token == token_s {
			if initiator {
				h.symmetricState.mixHash(rs.publicKey[:])
			} else {
				h.symmetricState.mixHash(s.publicKey[:])
			}
		} else {
			panic("Noise: token of pre-message not supported")
		}
	}

	h.messagePatterns = handshakePattern.messagePatterns

	return
}

// TODO: documentation
func (h *handshakeState) WriteMessage(payload []byte, messageBuffer *[]byte) (c1, c2 *cipherState, err error) {
	// is it our turn to write?
	if !h.shouldWrite {
		panic("Noise: unexpected call to WriteMessage should be ReadMessage")
	}
	// do we have a token to process?
	if len(h.messagePatterns) == 0 || len(h.messagePatterns[0]) == 0 {
		panic("Noise: no more tokens or message patterns to write")
	}

	// process the patterns
	for _, pattern := range h.messagePatterns[0] {

		if pattern == token_e {
			h.e = *GenerateKeypair()
			*messageBuffer = append(*messageBuffer, h.e.publicKey[:]...)
			h.symmetricState.mixHash(h.e.publicKey[:])

		} else if pattern == token_s {
			var ciphertext []byte
			ciphertext, err = h.symmetricState.encryptAndHash(h.s.publicKey[:])
			if err != nil {
				return
			}
			*messageBuffer = append(*messageBuffer, ciphertext...)

		} else if pattern == token_ee {
			h.symmetricState.mixKey(dh(h.e, h.re.publicKey))

		} else if pattern == token_es {
			if h.initiator {
				h.symmetricState.mixKey(dh(h.e, h.rs.publicKey))
			} else {
				h.symmetricState.mixKey(dh(h.s, h.re.publicKey))
			}

		} else if pattern == token_se {
			if h.initiator {
				h.symmetricState.mixKey(dh(h.s, h.re.publicKey))
			} else {
				h.symmetricState.mixKey(dh(h.e, h.rs.publicKey))
			}

		} else if pattern == token_ss {
			h.symmetricState.mixKey(dh(h.s, h.rs.publicKey))
		} else {
			panic("Noise: token not recognized")
		}
	}

	// Appends EncryptAndHash(payload) to the buffer
	var ciphertext []byte
	ciphertext, err = h.symmetricState.encryptAndHash(payload)
	if err != nil {
		return
	}
	*messageBuffer = append(*messageBuffer, ciphertext...)

	// are there more message patterns to process?
	if len(h.messagePatterns) == 1 {
		// If there are no more message patterns returns two new CipherState objects
		h.messagePatterns = nil
		c1, c2 = h.symmetricState.Split()
	} else {
		// remove the pattern from the messagePattern
		h.messagePatterns = h.messagePatterns[1:]
	}

	// change the direction
	h.shouldWrite = false

	return
}

// ReadMessage takes a byte sequence containing a Noise handshake message,
// and a payload_buffer to write the message's plaintext payload into.
func (h *handshakeState) ReadMessage(message []byte, payloadBuffer *[]byte) (c1, c2 *cipherState, err error) {
	// is it our turn to read?
	if h.shouldWrite {
		panic("Noise: unexpected call to ReadMessage should be WriteMessage")
	}
	// do we have a token to process?
	if len(h.messagePatterns) == 0 || len(h.messagePatterns[0]) == 0 {
		panic("Noise: no more message pattern to read")
	}

	// process the patterns
	offset := 0

	for _, pattern := range h.messagePatterns[0] {

		if pattern == token_e {
			if len(message[offset:]) < dhLen {
				return nil, nil, errors.New("Noise: the received ephemeral key is to short")
			}
			copy(h.re.publicKey[:], message[offset:offset+dhLen])
			offset += dhLen
			h.symmetricState.mixHash(h.re.publicKey[:])

		} else if pattern == token_s {

			tagLen := 0
			if h.symmetricState.cipherState.hasKey() {
				tagLen = 16
			}
			if len(message[offset:]) < dhLen+tagLen {
				return nil, nil, errors.New("Noise: the received static key is to short")
			}
			var plaintext []byte
			plaintext, err = h.symmetricState.decryptAndHash(message[offset : offset+dhLen+tagLen])
			if err != nil {
				return
			}
			// if we already know the remote static, compare
			copy(h.rs.publicKey[:], plaintext)
			offset += dhLen + tagLen

		} else if pattern == token_ee {
			h.symmetricState.mixKey(dh(h.e, h.re.publicKey))

		} else if pattern == token_es {
			if h.initiator {
				h.symmetricState.mixKey(dh(h.e, h.rs.publicKey))
			} else {
				h.symmetricState.mixKey(dh(h.s, h.re.publicKey))
			}

		} else if pattern == token_se {
			if h.initiator {
				h.symmetricState.mixKey(dh(h.s, h.re.publicKey))
			} else {
				h.symmetricState.mixKey(dh(h.e, h.rs.publicKey))
			}

		} else if pattern == token_ss {
			h.symmetricState.mixKey(dh(h.s, h.rs.publicKey))
		} else {
			panic("Noise: token not recognized")
		}
	}

	// Appends decrpyAndHash(payload) to the buffer
	var plaintext []byte
	plaintext, err = h.symmetricState.decryptAndHash(message[offset:])
	if err != nil {
		return
	}
	*payloadBuffer = append(*payloadBuffer, plaintext...)

	// remove the pattern from the messagePattern
	if len(h.messagePatterns) == 1 {
		// If there are no more message patterns returns two new CipherState objects
		h.messagePatterns = nil
		c1, c2 = h.symmetricState.Split()
	} else {
		h.messagePatterns = h.messagePatterns[1:]
	}

	// change the direction
	h.shouldWrite = true

	return
}

//
// Clearing stuff
//

// TODO: is there a better way to get rid of secrets in Go?
func (hs *handshakeState) clear() {
	hs.s.clear()
	hs.e.clear()
	hs.rs.clear()
	hs.re.clear()
}

// TODO: is there a better way to get rid of secrets in Go?
func (kp *keyPair) clear() {
	for i := 0; i < len(kp.privateKey); i++ {
		kp.privateKey[i] = 0
	}
	for i := 0; i < len(kp.publicKey); i++ {
		kp.publicKey[i] = 0
	}
}
