package noise

import (
	"bytes"
	"fmt"
	"testing"
)

func TestNoiseHandshake(t *testing.T) {

	// init
	initiatorKey := GenerateKeypair()
	responderKey := GenerateKeypair()

	initiator := Initialize("XX", true, nil, &initiatorKey, nil, &responderKey, nil)
	responder := Initialize("XX", false, nil, &responderKey, nil, &initiatorKey, nil)

	var bufferInitiator, bufferResponder []byte

	// 1. initiator "->e" - sends a pubkey in clear + "salut" in clear.
	initiator.WriteMessage([]byte("salut"), &bufferInitiator)

	// 1. responder "->e" - receives the public key, decrypts "salut"

	responder.ReadMessage(bufferInitiator, &bufferResponder)
	fmt.Printf("responder is receiving in clear: %s\n", bufferResponder)

	if !bytes.Equal(bufferResponder, []byte("salut")) {
		t.Error("first message failed")
	}

	// 2. responder "<-e, ee, s, es" - sends a public key in clear, DH, sends a static key encrypted
	bufferResponder = bufferResponder[:0]
	responder.WriteMessage([]byte("ca va ?"), &bufferResponder)

	// 2. initiator "<-e, ee, s, es" -
	bufferInitiator = bufferInitiator[:0]
	initiator.ReadMessage(bufferResponder, &bufferInitiator)
	fmt.Printf("initiator is receiving encrypted: %s\n", bufferInitiator)

	if !bytes.Equal(bufferInitiator, []byte("ca va ?")) {
		t.Error("first message failed")
	}

	// 3. "->s, se" - send last trip
	bufferInitiator = bufferInitiator[:0]
	initiatorCipherWrite, _ := initiator.WriteMessage([]byte("oui et toi ?"), &bufferInitiator)

	// 3. "->s, se" - receive last trip
	bufferResponder = bufferResponder[:0]
	responderCipherRead, _ := responder.ReadMessage(bufferInitiator, &bufferResponder)
	fmt.Printf("responder is receiving encrypted: %s\n", bufferResponder)

	if !bytes.Equal(bufferResponder, []byte("oui et toi ?")) {
		t.Error("first message failed")
	}

	// HANDSHAKE DONE!
	fmt.Println("handshake done!")

	// Try to send one message
	ciphertext, err := initiatorCipherWrite.EncryptWithAd([]byte{}, []byte("hello!"))
	if err != nil {
		panic(err)
	}

	fmt.Println("sending ciphertext:", ciphertext)

	plaintext, err := responderCipherRead.DecryptWithAd([]byte{}, ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Printf("receiving ciphertext: %s\n", plaintext)

	if !bytes.Equal(plaintext, []byte("hello!")) {
		t.Error("first message failed")
	}
}
