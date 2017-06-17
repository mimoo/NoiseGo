package disco

import (
	"strings"

	"github.com/mimoo/StrobeGo/strobe"
)

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
	strobeState strobe.Strobe
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

// This allows you to initialize a peer.
// * see `patterns` for a list of available handshakePatterns
// * initiator = false means the instance is for a responder
// * prologue is a byte string record of anything that happened prior the Noise handshakeState
// * s, e, rs, re are the local and remote static/ephemeral key pairs to be set (if they exist)
// the function returns a handshakeState object.
func Initialize(handshakePattern string, initiator bool, prologue []byte, s, e, rs, re *keyPair) (h handshakeState) {
	if _, ok := patterns[handshakePattern]; !ok {
		panic("the supplied handshakePattern does not exist")
	}

	h.strobeState = strobe.InitStrobe("DISCOv0.1.0_" + handshakePattern)

	h.strobeState.AD(false, prologue)

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
		if initiator {
			h.strobeState.AD(false, s.publicKey[:])
		} else {
			h.strobeState.AD(false, rs.publicKey[:])
		}
	}
	if strings.Contains(patterns[handshakePattern].responderPreMessagePattern, "s") {
		if initiator {
			h.strobeState.AD(false, rs.publicKey[:])
		} else {
			h.strobeState.AD(false, s.publicKey[:])
		}
	}

	h.messagePattern = patterns[handshakePattern].messagePattern

	return
}

func (h *handshakeState) WriteMessage(payload []byte, messageBuffer *[]byte) (c1 strobe.Strobe, c2 strobe.Strobe) {
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
			h.strobeState.Send_CLR(false, h.e.publicKey[:])
		} else if pattern == "s" {
			*messageBuffer = append(*messageBuffer, h.strobeState.Send_AEAD(h.s.publicKey[:], []byte{})...)
		} else if pattern == "ee" {
			h.strobeState.KEY(dh(h.e, h.re.publicKey))
		} else if pattern == "es" {
			if h.initiator {
				h.strobeState.KEY(dh(h.e, h.rs.publicKey))
			} else {
				h.strobeState.KEY(dh(h.s, h.re.publicKey))
			}
		} else if pattern == "se" {
			if h.initiator {
				h.strobeState.KEY(dh(h.s, h.re.publicKey))
			} else {
				h.strobeState.KEY(dh(h.e, h.rs.publicKey))
			}
		} else if pattern == "ss" {
			h.strobeState.KEY(dh(h.s, h.rs.publicKey))
		} else {
			panic("pattern not allowed")
		}
	}

	// Appends EncryptAndHash(payload) to the buffer
	*messageBuffer = append(*messageBuffer, h.strobeState.Send_AEAD(payload, []byte{})...)

	// remove the pattern from the messagePattern
	if len(h.messagePattern) == 1 {
		// If there are no more message patterns returns two new CipherState objects
		h.messagePattern = nil

		/*
			Here:
			- I could have used Strobe's PRF instead
			- maybe I should do a h.strobeState.ForceF() before cloning?
		*/

		c1 = h.strobeState.Clone()
		c2 = h.strobeState
		c1.KEY([]byte("initiator"))
		c2.KEY([]byte("responder"))

	} else {
		h.messagePattern = h.messagePattern[1:]
	}

	return
}

func (h *handshakeState) ReadMessage(message []byte, payloadBuffer *[]byte) (c1 strobe.Strobe, c2 strobe.Strobe) {
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
			h.strobeState.Recv_CLR(false, h.re.publicKey[:])
		} else if pattern == "s" {

			pubKey, ok := h.strobeState.Recv_AEAD(message[offset:offset+dhLen+16], []byte{})
			if !ok {
				// TODO: fail gracefuly
				panic("bad MAC")
			}
			offset += dhLen + 16
			copy(h.rs.publicKey[:], pubKey)

		} else if pattern == "ee" {
			h.strobeState.KEY(dh(h.e, h.re.publicKey))
		} else if pattern == "es" {
			if h.initiator {
				h.strobeState.KEY(dh(h.e, h.rs.publicKey))
			} else {
				h.strobeState.KEY(dh(h.s, h.re.publicKey))
			}
		} else if pattern == "se" {
			if h.initiator {
				h.strobeState.KEY(dh(h.s, h.re.publicKey))
			} else {
				h.strobeState.KEY(dh(h.e, h.rs.publicKey))
			}
		} else if pattern == "ss" {
			h.strobeState.KEY(dh(h.s, h.rs.publicKey))
		} else {
			panic("pattern not allowed")
		}
	}

	// Appends decrypted payload to the buffer
	plaintext, ok := h.strobeState.Recv_AEAD(message[offset:], []byte{})
	if !ok {
		// TODO: fail gracefuly
		panic("invalid MAC")
	}
	*payloadBuffer = append(*payloadBuffer, plaintext...)

	// remove the pattern from the messagePattern
	if len(h.messagePattern) == 1 {
		// If there are no more message patterns returns two new CipherState objects
		h.messagePattern = nil

		c1 = h.strobeState.Clone()
		c2 = h.strobeState
		c1.KEY([]byte("initiator"))
		c2.KEY([]byte("responder"))
	} else {
		h.messagePattern = h.messagePattern[1:]
	}
	return
}
