package noise

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/flynn/noise"
)

/*

this implementation:

type keyPair struct {
	privateKey [32]byte
	publicKey  [32]byte
}

flynn:

type DHKey struct {
	Private []byte
	Public  []byte
}

*/

func TestXX(t *testing.T) {

	// generate client key
	initiatorKey := GenerateKeypair()

	// generate flynn key
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	responderKey := cs.GenerateKeypair(rand.Reader)

	// init client
	/*
		var responderKeyStruct keyPair
		copy(responderKeyStruct.privateKey[:], responderKey.Private[:32])
		copy(responderKeyStruct.publicKey[:], responderKey.Public[:32])
	*/
	initiator := Initialize("XX", true, nil, &initiatorKey, nil, nil, nil)

	// init flynn
	hsR := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeXX,
		StaticKeypair: responderKey,
	})

	var bufferInitiator, bufferResponder []byte

	// 1. initiator "->e" - sends a pubkey in clear + "salut" in clear.
	fmt.Println(" initiator ->e")
	initiator.WriteMessage([]byte("salut"), &bufferInitiator)

	// 1. responder "->e" - receives the public key, decrypts "salut"
	fmt.Println(" responder ->e")
	bufferResponder, _, _, err := hsR.ReadMessage(nil, bufferInitiator) // will write "E"

	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(bufferResponder, []byte("salut")) {
		t.Error("first message failed")
	}

	// 2. responder "<-e, ee, s, es" - sends a public key in clear, DH, sends a static key encrypted
	fmt.Println(" responder <-e, ee, s, es")
	bufferResponder, _, _ = hsR.WriteMessage(nil, []byte("ca va ?"))

	// 2. initiator "<-e, ee, s, es" -
	fmt.Println(" initiator <-e, ee, s, es")
	bufferInitiator = bufferInitiator[:0]
	initiator.ReadMessage(bufferResponder, &bufferInitiator)

	if !bytes.Equal(bufferInitiator, []byte("ca va ?")) {
		t.Error("second message failed", bufferInitiator)
	}

	// 3. "->s, se" - send last trip
	fmt.Println(" initiator ->s, se")
	bufferInitiator = bufferInitiator[:0]
	initiatorCipherWrite, initiatorCipherRead := initiator.WriteMessage([]byte("oui et toi ?"), &bufferInitiator)

	// 3. "->s, se" - receive last trip
	fmt.Println(" responder ->s, se")
	bufferResponder, responderCipherRead, responderCipherWrite, err := hsR.ReadMessage(nil, bufferInitiator) // will write "S" then "SE"

	if err != nil {
		t.Error(err)
		return
	}

	if !bytes.Equal(bufferResponder, []byte("oui et toi ?")) {
		t.Error("third message failed", bufferInitiator)
	}

	// Try to send one message from the initiator
	ciphertext1, err := initiatorCipherWrite.EncryptWithAd([]byte{}, []byte("hello!"))
	if err != nil {
		panic(err)
	}

	plaintext1, err := responderCipherRead.Decrypt(nil, []byte{}, ciphertext1)

	if !bytes.Equal(plaintext1, []byte("hello!")) {
		t.Error("fourth message failed", bufferInitiator)
	}

	// Try to send a message from the responder
	ciphertext2 := responderCipherWrite.Encrypt(nil, []byte{}, []byte("hehe, this is a longer message"))
	plaintext2, err := initiatorCipherRead.DecryptWithAd([]byte{}, ciphertext2)

	if !bytes.Equal(plaintext2, []byte("hehe, this is a longer message")) {
		t.Error("fifth message failed", bufferInitiator)
	}

}
