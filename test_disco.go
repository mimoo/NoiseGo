package main

import (
	"fmt"

	"./disco"
)

func main() {

	// init
	initiatorKey := disco.GenerateKeypair()
	responderKey := disco.GenerateKeypair()

	initiator := disco.Initialize("XX", true, nil, &initiatorKey, nil, &responderKey, nil)
	responder := disco.Initialize("XX", false, nil, &responderKey, nil, &initiatorKey, nil)

	var bufferInitiator, bufferResponder []byte

	// 1. initiator "->e" - sends a pubkey in clear + "salut" in clear.
	initiator.WriteMessage([]byte("salut"), &bufferInitiator)

	// 1. responder "->e" - receives the public key, decrypts "salut"

	responder.ReadMessage(bufferInitiator, &bufferResponder)
	fmt.Printf("responder is receiving in clear: %s\n", bufferResponder)

	// 2. responder "<-e, ee, s, es" - sends a public key in clear, DH, sends a static key encrypted
	bufferResponder = bufferResponder[:0]
	responder.WriteMessage([]byte("ca va?"), &bufferResponder)

	// 2. initiator "<-e, ee, s, es" -
	bufferInitiator = bufferInitiator[:0]
	initiator.ReadMessage(bufferResponder, &bufferInitiator)
	fmt.Printf("initiator is receiving encrypted: %s\n", bufferInitiator)

	// 3. "->s, se" - send last trip
	bufferInitiator = bufferInitiator[:0]
	initiatorCipherWrite, _ := initiator.WriteMessage([]byte("oui et toi?"), &bufferInitiator)

	// 3. "->s, se" - receive last trip
	bufferResponder = bufferResponder[:0]
	responderCipherRead, _ := responder.ReadMessage(bufferInitiator, &bufferResponder)
	fmt.Printf("responder is receiving encrypted: %s\n", bufferResponder)

	fmt.Println("handshake done!")
	// HANDSHAKE DONE!
	ciphertext := initiatorCipherWrite.Send_ENC(false, []byte("hello!"))

	fmt.Println("sending ciphertext:", ciphertext)
	plaintext := responderCipherRead.Recv_ENC(false, ciphertext)

	fmt.Printf("receiving ciphertext: %s\n", plaintext)
}
