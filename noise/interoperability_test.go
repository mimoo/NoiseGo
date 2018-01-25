package noise

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/flynn/noise"
)

/*
The following test the flynn/noise implementation.

this implementation uses the following KeyPair structure:

type KeyPair struct {
	privateKey [32]byte
	publicKey  [32]byte
}

while flynn/noise uses the following:

type DHKey struct {
	Private []byte
	Public  []byte
}
*/

func TestFlynnNoise(t *testing.T) {

	// generate client key
	initiatorKey := GenerateKeypair(nil)

	// generate flynn key
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	responderKey, _ := cs.GenerateKeypair(rand.Reader)

	// init client

	//var responderKeyStruct keyPair
	//copy(responderKeyStruct.privateKey[:], responderKey.Private[:32])
	//copy(responderKeyStruct.publicKey[:], responderKey.Public[:32])

	initiator := initialize(Noise_XX, true, nil, initiatorKey, nil, nil, nil)

	// init flynn
	hsR, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeXX,
		StaticKeypair: responderKey,
	})

	var bufferInitiator, bufferResponder []byte

	// 1. initiator "->e" - sends a pubkey in clear + "salut" in clear.
	t.Log(" initiator ->e")
	initiator.writeMessage([]byte("salut"), &bufferInitiator)

	// 1. responder "->e" - receives the public key, decrypts "salut"
	t.Log(" responder ->e")
	bufferResponder, _, _, err := hsR.ReadMessage(nil, bufferInitiator) // will write "E"

	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(bufferResponder, []byte("salut")) {
		t.Fatal("first message failed")
		return
	}

	// 2. responder "<-e, ee, s, es" - sends a public key in clear, DH, sends a static key encrypted
	t.Log(" responder <-e, ee, s, es")
	bufferResponder, _, _, _ = hsR.WriteMessage(nil, []byte("ca va ?"))

	// 2. initiator "<-e, ee, s, es" -
	t.Log(" initiator <-e, ee, s, es")
	bufferInitiator = bufferInitiator[:0]
	initiator.readMessage(bufferResponder, &bufferInitiator)

	if !bytes.Equal(bufferInitiator, []byte("ca va ?")) {
		t.Fatal("second message failed", bufferInitiator)
		return
	}

	// 3. "->s, se" - send last trip
	t.Log(" initiator ->s, se")
	bufferInitiator = bufferInitiator[:0]
	initiatorCipherWrite, initiatorCipherRead, err := initiator.writeMessage([]byte("oui et toi ?"), &bufferInitiator)

	if err != nil {
		t.Fatal(err)
		return
	}

	// 3. "->s, se" - receive last trip
	t.Log(" responder ->s, se")
	bufferResponder, responderCipherRead, responderCipherWrite, err := hsR.ReadMessage(nil, bufferInitiator) // will write "S" then "SE"

	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(bufferResponder, []byte("oui et toi ?")) {
		t.Fatal("third message failed")
		return
	}

	// Try to send one message from the initiator
	ciphertext1, err := initiatorCipherWrite.encryptWithAd([]byte{}, []byte("hello!"))
	if err != nil {
		t.Fatal("fourth message failed to encrypt", err)
		return
	}

	plaintext1, err := responderCipherRead.Decrypt(nil, []byte{}, ciphertext1)
	if err != nil || !bytes.Equal(plaintext1, []byte("hello!")) {
		t.Fatal("fourth message failed")
		return
	}

	// Try to send a message from the responder
	ciphertext2 := responderCipherWrite.Encrypt(nil, []byte{}, []byte("hehe, this is a longer message"))
	plaintext2, err := initiatorCipherRead.decryptWithAd([]byte{}, ciphertext2)
	if err != nil || !bytes.Equal(plaintext2, []byte("hehe, this is a longer message")) {
		t.Fatal("fifth message failed")
		return
	}
}
