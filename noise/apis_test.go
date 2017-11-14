package noise

import (
	"os"
	"testing"
)

func TestCreationKeys(t *testing.T) {

	// temporary files
	noiseKeyPairFile := "./noiseKeyPairFile"
	defer os.Remove(noiseKeyPairFile)
	rootPrivateKeyFile := "./rootPrivateKeyFile"
	defer os.Remove(rootPrivateKeyFile)
	rootPublicKeyFile := "./rootPublicKeyFile"
	defer os.Remove(rootPublicKeyFile)

	// Generate Noise Key pair
	keyPair, err := GenerateAndSaveNoiseKeyPair(noiseKeyPairFile)
	if err != nil {
		t.Error("Noise key pair couldn't be written on disk")
		return
	}
	// Load Noise Key pair
	keyPairTemp, err := LoadNoiseKeyPair(noiseKeyPairFile)
	if err != nil {
		t.Error("Noise key pair couldn't be loaded from disk")
		return
	}
	// compare
	for i := 0; i < 32; i++ {
		if keyPair.PublicKey[i] != keyPairTemp.PublicKey[i] ||
			keyPair.PrivateKey[i] != keyPairTemp.PrivateKey[i] {
			t.Error("Noise key pair generated and loaded are different")
			return
		}
	}
	// generate root key
	err = GenerateAndSaveNoiseRootKeyPair(rootPrivateKeyFile, rootPublicKeyFile)
	if err != nil {
		t.Error("Noise key pair couldn't be written on disk")
		return
	}

	// load private root key
	rootPriv, err := LoadNoiseRootPrivateKey(rootPrivateKeyFile)
	if err != nil {
		t.Error("Noise root private key couldn't be loaded from disk")
		return
	}
	// load public root key
	rootPub, err := LoadNoiseRootPublicKey(rootPublicKeyFile)
	if err != nil {
		t.Error("Noise root public key couldn't be loaded from disk")
		return
	}

	// create a proof
	proof := CreateStaticPublicKeyProof(rootPriv, keyPair)

	// verify the proof
	verifior := CreatePublicKeyVerifier(rootPub)
	if verifior(keyPair.PublicKey[:], proof) != true {
		t.Error("cannot verify proof")
		return
	}

	// end
}
