package noise

// The following constants represent the details of this Noise implementation.
const (
	NoiseDraftVersion = "33"
	NoiseDH           = "25519"
	NoiseAEAD         = "ChaChaPoly"
	NoiseHASH         = "SHA256"
)

// The following constants represent constants from the Noise specification.
const (
	// A noise message's length. The specification says it should be 65535,
	// but the specification forgets to mention the 2-byte of required header (length)
	NoiseMessageLength    = 65535 - 2
	NoiseTagLength        = 16
	NoiseMaxPlaintextSize = NoiseMessageLength - NoiseTagLength
)

type Config struct {
	// If patterns in which the remote peer sends a unknown
	// static public key as part of the handshake, this callback is
	// MANDATORY in order to attest validate it.
	PublicKeyVerifier func(publicKey, proof []byte) bool
	// If patterns in which a static public key is sent as part of
	// the handshake, this proof is MANDATORY.
	StaticPublicKeyProof []byte

	HandshakePattern              noiseHandshakeType
	Prologue                      []byte
	KeyPair, EphemeralKeyPair     *keyPair
	RemoteKey, EphemeralRemoteKey *keyPair

	// This forces the peers to write and read on a single socket. If a half-duplex protocol is used, it is imperative that the peers take turn to write and read on the socket.
	HalfDuplex bool
}
