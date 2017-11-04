package noise

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

//
// The following code defines the X25519, chacha20poly1305, SHA-256 suite.
//

const (
	dhLen    = 32 // A constant specifying the size in bytes of public keys and DH outputs. For security reasons, dhLen must be 32 or greater.
	hashLen  = 32
	blockLen = 64
)

// 4.1. DH functions

// TODO: store that in *[32]byte or []byte
// TODO: urgent, privateKey and publicKey should be public, especially if I'm expecting
// people to manipulate them directly to fill the publicKey
// or maybe I shouldn't allow people to do that and only make them use the utility functions?
type KeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// GenerateKeyPair creates a X25519 keyPair.
func GenerateKeypair() *KeyPair {

	var keyPair KeyPair

	if _, err := rand.Read(keyPair.PrivateKey[:]); err != nil {
		panic(err)
	}

	curve25519.ScalarBaseMult(&keyPair.PublicKey, &keyPair.PrivateKey)

	return &keyPair
}

func dh(keyPair KeyPair, publicKey [32]byte) (shared [32]byte) {

	curve25519.ScalarMult(&shared, &keyPair.PrivateKey, &publicKey)

	return
}

// 4.2. Cipher functions
// TODO: should this really panic? decrypts return an error, this does not
func encrypt(k [32]byte, n uint64, ad, plaintext []byte) (ciphertext []byte) {

	cipher, err := chacha20poly1305.New(k[:])
	if err != nil {
		panic(err)
	}

	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], n)
	// TODO: storage can be re-used by doing Seal(plaintext[:0], ...)
	// if we do that, we could think of creating a single buffer of NoiseMessageLength for all operations
	ciphertext = cipher.Seal(nil, append([]byte{0, 0, 0, 0}, nonce[:]...), plaintext, ad)

	return
}

func decrypt(k [32]byte, n uint64, ad, ciphertext []byte) (plaintext []byte, err error) {

	cipher, err := chacha20poly1305.New(k[:])
	if err != nil {
		return
	}

	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], n)
	plaintext, err = cipher.Open(nil, append([]byte{0, 0, 0, 0}, nonce[:]...), ciphertext, ad)
	return
}

func rekey(k [32]byte) (newkey [32]byte) {

	copy(newkey[:], encrypt(k, math.MaxUint64, []byte{}, bytes.Repeat([]byte{0}, 32))[:32])

	return
}

// 4.3. Hash functions

func hash(data []byte) [32]byte {
	return sha256.Sum256(data)
	//return K12.NewK12([]byte("noise_hash"))
}

func hmacHash(key, data []byte) []byte {
	// return K12Sum([]byte()"noise_mac"), append(key, data...), out)
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hkdf(chainingKey, inputKeyMaterial []byte, numOutputs int) (output []byte) {

	if numOutputs != 2 && numOutputs != 3 {
		panic("numOutputs should be 2 or 3")
	}

	// kdf := K12.NewK12([]byte("noise_kdf")])
	// hash.Write(append(chainingKey, inputKeyMaterial...))
	// output = make([]byte, 32 * numOutputs)
	// hash.Read(output)
	// return
	tempKey := hmacHash(chainingKey, inputKeyMaterial)
	output = hmacHash(tempKey, []byte{0x01})
	output = append(output, hmacHash(tempKey, append(output, 0x02))...)

	if numOutputs == 2 {
		return
	}
	output = append(output, hmacHash(tempKey, append(output[32:], 0x03))...)
	return
}
