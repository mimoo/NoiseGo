package noise

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/crypto/curve25519"
)

//
// Json parsing
//

type Message struct {
	Payload    string `json:"payload"`
	Ciphertext string `json:"ciphertext"`
}

type Vector struct {
	ProtocolName     string    `json:"protocol_name"`
	InitPrologue     string    `json:"init_prologue"`
	InitStatic       string    `json:"init_static"`
	InitEphemeral    string    `json:"init_ephemeral"`
	InitRemoteStatic string    `json:"init_remote_static"`
	RespPrologue     string    `json:"resp_prologue"`
	RespStatic       string    `json:"resp_static"`
	RespEphemeral    string    `json:"resp_ephemeral"`
	RespRemoteStatic string    `json:"resp_remote_static"`
	HandshakeHash    string    `json:"handshake_hash"`
	Messages         []Message `json:"messages"`
}

type cacophony struct {
	Vectors []Vector
}

//
// Internal representation of the test vectors
//

type message struct {
	payload    []byte
	ciphertext []byte
}

type vector struct {
	initPrologue     []byte
	initStatic       []byte
	initEphemeral    []byte
	initRemoteStatic []byte

	respPrologue     []byte
	respStatic       []byte
	respEphemeral    []byte
	respRemoteStatic []byte
	messages         []message
}

var testVectors map[string]vector

//
// Retrieve test vectors from Cacophony
//
func init() {
	// open cacophony test vectors
	raw, err := ioutil.ReadFile("./vectors/cacophony.txt")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	// parse the JSON
	var parsedTestVectors cacophony
	json.Unmarshal(raw, &parsedTestVectors)
	// only get what I want into the testVectors map
	testVectors = make(map[string]vector)
	for _, hexVector := range parsedTestVectors.Vectors {
		if n := hexVector.ProtocolName; n == "Noise_N_25519_ChaChaPoly_SHA256" || n == "Noise_KK_25519_ChaChaPoly_SHA256" || n == "Noise_NX_25519_ChaChaPoly_SHA256" || n == "Noise_NK_25519_ChaChaPoly_SHA256" || n == "Noise_XX_25519_ChaChaPoly_SHA256" {
			initPrologue, _ := hex.DecodeString(hexVector.InitPrologue)
			initStatic, _ := hex.DecodeString(hexVector.InitStatic)
			initEphemeral, _ := hex.DecodeString(hexVector.InitEphemeral)
			initRemoteStatic, _ := hex.DecodeString(hexVector.InitRemoteStatic)
			respPrologue, _ := hex.DecodeString(hexVector.RespPrologue)
			respStatic, _ := hex.DecodeString(hexVector.RespStatic)
			respEphemeral, _ := hex.DecodeString(hexVector.RespEphemeral)
			respRemoteStatic, _ := hex.DecodeString(hexVector.RespRemoteStatic)
			messages := make([]message, len(hexVector.Messages))
			for idx, hexMessage := range hexVector.Messages {
				payload, _ := hex.DecodeString(hexMessage.Payload)
				ciphertext, _ := hex.DecodeString(hexMessage.Ciphertext)
				messages[idx] = message{payload, ciphertext}
			}
			byteVector := vector{
				initPrologue:     initPrologue,
				initStatic:       initStatic,
				initEphemeral:    initEphemeral,
				initRemoteStatic: initRemoteStatic,
				respPrologue:     respPrologue,
				respStatic:       respStatic,
				respEphemeral:    respEphemeral,
				respRemoteStatic: respRemoteStatic,
				messages:         messages,
			}
			testVectors[hexVector.ProtocolName] = byteVector
		}
	}

}

/*
N(rs):
  <- s
  ...
  -> e, es
*/
func Test_Noise_N_25519_ChaChaPoly_SHA256(t *testing.T) {
	testVector := testVectors["Noise_N_25519_ChaChaPoly_SHA256"]
	// setup initiator ephemeral
	var e keyPair
	copy(e.privateKey[:], testVector.initEphemeral)
	curve25519.ScalarBaseMult(&e.publicKey, &e.privateKey)
	// setup initiator remote static key
	var rs keyPair
	copy(rs.publicKey[:], testVector.initRemoteStatic)
	// go through handshake
	initiator := initialize(Noise_N, true, testVector.initPrologue, nil, nil, &rs, nil)
	initiator.debugEphemeral = &e
	var handshakeMsg []byte
	c1, _, err := initiator.writeMessage(testVector.messages[0].payload, &handshakeMsg)

	if !bytes.Equal(testVector.messages[0].ciphertext, handshakeMsg) {
		t.Fatal("text vector failed")
	}

	if c1 == nil || err != nil {
		t.Fatal("cannot finish handshake")
	}
	// go through messages
	for _, message := range testVector.messages[1:] {
		ciphertext, err := c1.encryptWithAd([]byte{}, message.payload)
		if err != nil {
			t.Fatal("message failed to encrypt", err)
		}
		if !bytes.Equal(message.ciphertext, ciphertext) {
			t.Fatal("text vector failed")
		}
	}
}

/*
KK(s, rs):
  -> s
  <- s
  ...
  -> e, es, ss
  <- e, ee, se
*/
func Test_Noise_KK_25519_ChaChaPoly_SHA256(t *testing.T) {
	testVector := testVectors["Noise_KK_25519_ChaChaPoly_SHA256"]
	// setup initiator static
	var s keyPair
	copy(s.privateKey[:], testVector.initStatic)
	curve25519.ScalarBaseMult(&s.publicKey, &s.privateKey)
	// setup responder static
	var rs keyPair
	copy(rs.privateKey[:], testVector.respStatic)
	curve25519.ScalarBaseMult(&rs.publicKey, &rs.privateKey)
	// initialize(handshakeType, initiator, prologue, s, e, rs, re)
	initiator := initialize(Noise_KK, true, testVector.initPrologue, &s, nil, &rs, nil)
	responder := initialize(Noise_KK, false, testVector.respPrologue, &rs, nil, &s, nil)
	// setup initiator ephemeral
	var e keyPair
	copy(e.privateKey[:], testVector.initEphemeral)
	curve25519.ScalarBaseMult(&e.publicKey, &e.privateKey)
	initiator.debugEphemeral = &e
	// setup responder ephemeral
	var re keyPair
	copy(re.privateKey[:], testVector.respEphemeral)
	curve25519.ScalarBaseMult(&re.publicKey, &re.privateKey)
	responder.debugEphemeral = &re
	// go through test vectors
	handshakeComplete := false
	postHandshakeClientWriting := true
	var initiator_c1, initiator_c2, responder_c1, responder_c2 *cipherState
	for _, message := range testVector.messages {
		if !handshakeComplete {
			if initiator.shouldWrite {
				var ciphertext []byte
				var plaintext []byte
				initiator_c1, initiator_c2, _ = initiator.writeMessage(message.payload, &ciphertext)
				responder_c1, responder_c2, _ = responder.readMessage(ciphertext, &plaintext)
				if !bytes.Equal(message.ciphertext, ciphertext) {
					t.Fatal("initiator's message failed")
				}
				if !bytes.Equal(message.payload, plaintext) {
					t.Fatal("responder's message failed")
				}
				if initiator_c1 != nil {
					handshakeComplete = true
					fmt.Println("handshake complete!")
					if initiator_c1.k != responder_c1.k || initiator_c2.k != responder_c2.k {
						t.Fatal("c1 and c2 do not match")
					}
				}
			} else {
				var ciphertext []byte
				var plaintext []byte
				responder_c1, responder_c2, _ = responder.writeMessage(message.payload, &ciphertext)
				initiator_c1, initiator_c2, _ = initiator.readMessage(ciphertext, &plaintext)
				if !bytes.Equal(message.ciphertext, ciphertext) {
					t.Fatal("responder's message failed")
				}
				if !bytes.Equal(message.payload, plaintext) {
					t.Fatal("initiator's message failed")
				}
				if initiator_c1 != nil {
					handshakeComplete = true
					fmt.Println("handshake complete!")
					if initiator_c1.k != responder_c1.k || initiator_c2.k != responder_c2.k {
						t.Fatal("c1 and c2 do not match")
					}
				}
			}
		} else {
			if postHandshakeClientWriting {
				ciphertext, err := initiator_c1.encryptWithAd([]byte{}, message.payload)
				if err != nil {
					t.Fatal("message failed to encrypt", err)
				}
				if !bytes.Equal(message.ciphertext, ciphertext) {
					t.Fatal("bad encryption")
				}
				plaintext, err := responder_c1.decryptWithAd([]byte{}, ciphertext)
				if err != nil {
					t.Fatal("message failed to decrypt", err)
				}
				if !bytes.Equal(message.payload, plaintext) {
					t.Fatal("bad decryption")
				}
				postHandshakeClientWriting = false
			} else {
				ciphertext, err := responder_c2.encryptWithAd([]byte{}, message.payload)
				if err != nil {
					t.Fatal("message failed to encrypt", err)
				}
				if !bytes.Equal(message.ciphertext, ciphertext) {
					t.Fatal("bad encryption")
				}
				plaintext, err := initiator_c2.decryptWithAd([]byte{}, ciphertext)
				if err != nil {
					t.Fatal("message failed to decrypt", err)
				}
				if !bytes.Equal(message.payload, plaintext) {
					t.Fatal("bad decryption")
				}
				postHandshakeClientWriting = true
			}
		}
	}
}
