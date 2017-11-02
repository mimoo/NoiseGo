package noise

//
// Handshake Patterns
//

type noiseHandshakeType int8

const (
	// NoiseN is a one-way pattern where a client can send
	// data to a server with a known static key. The server
	// can only receive data and cannot reply back.
	Noise_N noiseHandshakeType = iota

	// NoiseKK is a pattern where both the client static key and the
	// server static key are known.
	Noise_KK

	// NoiseNX is a "HTTPS"-like pattern where the client is
	// not authenticated, and the static public key of the server
	// is transmitted during the handshake. It is the responsability of the client to validate the received key properly.
	Noise_NX

	// Noise_NK is a "Public Key Pinning"-like pattern where the client
	// is not authenticated, and the static public key of the server
	// is already known.
	Noise_NK

	// NoiseXX is a pattern where both static keys are transmitted.
	// It is the responsability of the server and of the client to
	// validate the received keys properly.
	Noise_XX
)

type token uint8

const (
	token_e token = iota
	token_s
	token_es
	token_se
	token_ss
	token_ee
)

type messagePattern []token

type handshakePattern struct {
	name               string
	preMessagePatterns []messagePattern
	messagePatterns    []messagePattern
}

// TODO: add more patterns
var patterns = map[noiseHandshakeType]handshakePattern{

	// 7.2. One-way patterns

	Noise_N: handshakePattern{
		name: "N",
		preMessagePatterns: []messagePattern{
			messagePattern{},        // →
			messagePattern{token_s}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e, token_es}, // →
		},
	},

	//
	// 7.3. Interactive patterns
	//

	Noise_KK: handshakePattern{
		name: "KK",
		preMessagePatterns: []messagePattern{
			messagePattern{token_s}, // →
			messagePattern{token_s}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e, token_es, token_ss}, // →
			messagePattern{token_e, token_ee, token_se}, // ←
		},
	},

	Noise_NX: handshakePattern{
		name: "NX",
		preMessagePatterns: []messagePattern{
			messagePattern{}, // →
			messagePattern{}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e},                              // →
			messagePattern{token_e, token_ee, token_s, token_es}, // ←
		},
	},

	Noise_NK: handshakePattern{
		name: "NK",
		preMessagePatterns: []messagePattern{
			messagePattern{},        // →
			messagePattern{token_s}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e, token_es}, // →
			messagePattern{token_e, token_ee}, // ←
		},
	},

	Noise_XX: handshakePattern{
		name: "XX",
		preMessagePatterns: []messagePattern{
			messagePattern{}, // →
			messagePattern{}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e},                              // →
			messagePattern{token_e, token_ee, token_s, token_es}, // ←
			messagePattern{token_s, token_se},                    // →
		},
	},
}
