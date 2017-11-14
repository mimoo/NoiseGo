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

//
// Test the following patterns
//

var patternsToTest = []struct {
	protocolName string
	patternName  noiseHandshakeType
}{
	{"Noise_N_25519_ChaChaPoly_SHA256", Noise_N},
	{"Noise_X_25519_ChaChaPoly_SHA256", Noise_X},
	{"Noise_K_25519_ChaChaPoly_SHA256", Noise_K},
	{"Noise_KK_25519_ChaChaPoly_SHA256", Noise_KK},
	{"Noise_NX_25519_ChaChaPoly_SHA256", Noise_NX},
	{"Noise_NK_25519_ChaChaPoly_SHA256", Noise_NK},
	{"Noise_XX_25519_ChaChaPoly_SHA256", Noise_XX},
}

func TestPatterns(t *testing.T) {
	for _, pattern := range patternsToTest {
		testVector := testVectors[pattern.protocolName]
		initiator, responder := setupInitiatorAndResponder(pattern.patternName, testVector)
		oneWayPattern := false
		if pn := pattern.patternName; pn == Noise_N || pn == Noise_K || pn == Noise_X {
			oneWayPattern = true
		}
		goThroughTestVectors(t, &initiator, &responder, testVector.messages, oneWayPattern)
	}
}

//
// Core functions (title says everything)
//

func setupInitiatorAndResponder(patternName noiseHandshakeType, testVector vector) (handshakeState, handshakeState) {
	var init_s, init_rs, resp_s, resp_rs *KeyPair
	// setup initiator static
	if len(testVector.initStatic) > 0 {
		var static KeyPair
		copy(static.PrivateKey[:], testVector.initStatic)
		curve25519.ScalarBaseMult(&static.PublicKey, &static.PrivateKey)
		init_s = &static
	}
	// setup initiator remote static
	if len(testVector.initRemoteStatic) > 0 {
		var static KeyPair
		copy(static.PublicKey[:], testVector.initRemoteStatic)
		init_rs = &static
	}
	// setup responder static
	if len(testVector.respStatic) > 0 {
		var static KeyPair
		copy(static.PrivateKey[:], testVector.respStatic)
		curve25519.ScalarBaseMult(&static.PublicKey, &static.PrivateKey)
		resp_s = &static
	}
	// setup responder remote static
	if len(testVector.respRemoteStatic) > 0 {
		var static KeyPair
		copy(static.PublicKey[:], testVector.respRemoteStatic)
		resp_rs = &static
	}
	// initialize(handshakeType, initiator, prologue, s, e, rs, re)
	initiator := initialize(patternName, true, testVector.initPrologue, init_s, nil, init_rs, nil)
	responder := initialize(patternName, false, testVector.respPrologue, resp_s, nil, resp_rs, nil)
	// setup initiator ephemeral
	if len(testVector.initEphemeral) > 0 {
		var e KeyPair
		copy(e.PrivateKey[:], testVector.initEphemeral)
		curve25519.ScalarBaseMult(&e.PublicKey, &e.PrivateKey)
		initiator.debugEphemeral = &e
	}
	// setup responder ephemeral
	if len(testVector.respEphemeral) > 0 {
		var re KeyPair
		copy(re.PrivateKey[:], testVector.respEphemeral)
		curve25519.ScalarBaseMult(&re.PublicKey, &re.PrivateKey)
		responder.debugEphemeral = &re
	}
	//
	return initiator, responder
}

func goThroughTestVectors(t *testing.T, initiator, responder *handshakeState, messages []message, oneWayPattern bool) {
	whoseTurnIsIt := true
	handshakeComplete := false
	var initiator_c1, initiator_c2, responder_c1, responder_c2 *cipherState
	for _, message := range messages {
		if !handshakeComplete {
			if whoseTurnIsIt {
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
					if initiator_c1.k != responder_c1.k || initiator_c2.k != responder_c2.k {
						t.Fatal("c1 and c2 do not match")
					}
				}
			}
		} else {
			if whoseTurnIsIt {
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
			}
		}
		if !oneWayPattern {
			whoseTurnIsIt = !whoseTurnIsIt
		}
	}
}
