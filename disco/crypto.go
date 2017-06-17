/*
	This is a readable implementation of Noisefunctions are implemented following the Noise specification
http://noiseprotocol.org/noise.html
*/

package disco

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

//
// The following code defines the X25519, chacha20poly1305, SHA-256 suite.
//

const (
	dhLen = 32 // A constant specifying the size in bytes of public keys and DH outputs. For security reasons, dhLen must be 32 or greater.
)

// 4.1. DH functions

type keyPair struct {
	privateKey [32]byte
	publicKey  [32]byte
}

func GenerateKeypair() (keyPair keyPair) {

	if _, err := rand.Read(keyPair.privateKey[:]); err != nil {
		// TODO: panic here really?
		panic(err)
	}

	curve25519.ScalarBaseMult(&keyPair.publicKey, &keyPair.privateKey)

	return
}

func dh(keyPair keyPair, publicKey [32]byte) []byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &keyPair.privateKey, &publicKey)

	return shared[:]
}
