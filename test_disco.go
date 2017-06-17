package main

import (
	"fmt"

	"./disco"
)

func main() {
	fmt.Println("\n==== START =====\n")
	fmt.Println("\n==== START =====\n")
	fmt.Println("\n==== START =====\n")
	fmt.Println("\n==== START =====\n")
	fmt.Println("\n==== START =====\n")

	// init
	initiatorKey := disco.GenerateKeypair()
	responderKey := disco.GenerateKeypair()

	initiator := disco.Initialize("XX", true, nil, &initiatorKey, nil, &responderKey, nil)
	responder := disco.Initialize("XX", false, nil, &responderKey, nil, &initiatorKey, nil)

	var bufferInitiator, bufferResponder []byte

	// 1. initiator "->e" - sends a pubkey in clear + "salut" in clear.
	fmt.Println("\n==== initiator ->e =====\n")
	initiator.WriteMessage([]byte("salut"), &bufferInitiator)

	// 1. responder "->e" - receives the public key, decrypts "salut"
	fmt.Println("\n==== responder ->e =====\n")

	responder.ReadMessage(bufferInitiator, &bufferResponder)
	fmt.Printf("responder is receiving in clear: %s\n", bufferResponder)

	// 2. responder "<-e, ee, s, es" - sends a public key in clear, DH, sends a static key encrypted
	fmt.Println("\n==== responder <-e, ee, s, es =====\n")
	bufferResponder = bufferResponder[:0]
	responder.WriteMessage([]byte("ca va?"), &bufferResponder)

	// 2. initiator "<-e, ee, s, es" -
	fmt.Println("\n==== initiator <-e, ee, s, es =====\n")
	bufferInitiator = bufferInitiator[:0]
	initiator.ReadMessage(bufferResponder, &bufferInitiator)
	fmt.Printf("initiator is receiving encrypted: %s\n", bufferInitiator)

	// 3. "->s, se" - send last trip
	fmt.Println("\n==== initiator ->s, se =====\n")
	bufferInitiator = bufferInitiator[:0]
	initiatorCipherWrite, initiatorCipherRead := initiator.WriteMessage([]byte("oui et toi?"), &bufferInitiator)
	initiator = nil // deleting the handshakeState

	// 3. "->s, se" - receive last trip
	fmt.Println("\n==== responder ->s, se =====\n")
	bufferResponder = bufferResponder[:0]
	responderCipherRead, responderCipherWrite := responder.ReadMessage(bufferInitiator, &bufferResponder)
	responder = nil // deleting the handshakeState
	fmt.Printf("responder is receiving encrypted: %s\n", bufferResponder)

	fmt.Println("\n==== handshake done =====\n")
	// HANDSHAKE DONE!
	fmt.Println("\n==== initiator sending ciphertext =====\n")
	ciphertext := initiatorCipherWrite.Send_AEAD([]byte("hello!"), []byte{})

	fmt.Println("\n==== responder receiving ciphertext =====\n")
	fmt.Println("sending ciphertext:", ciphertext)
	plaintext, ok := responderCipherRead.Recv_AEAD(ciphertext, []byte{})
	if !ok {
		panic("bad ciphertext")
	}
	fmt.Printf("receiving ciphertext: %s\n", plaintext)

	fmt.Println("\n==== responder replying =====\n")
	ciphertext = responderCipherWrite.Send_AEAD([]byte("what's up?!"), []byte{})

	fmt.Println("\n==== initiator getting the reply =====\n")
	plaintext, ok = initiatorCipherRead.Recv_AEAD(ciphertext, []byte{})
	if !ok {
		panic("bad ciphertext")
	}
	fmt.Printf("receiving ciphertext: %s\n", plaintext)

}
