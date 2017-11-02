package noise

//
// Handshake Patterns
//

type noiseHandshakeType int8

const (
	//
	// 7.2. One-way patterns
	//

	// NoiseN is a one-way pattern
	// NoiseN = No static key for sender
	NoiseN noiseHandshakeType = iota

	// 7.3. Interactive patterns
	NoiseNN
	NoiseXX

	// Not implemented

	NoiseK
	NoiseX
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

	NoiseN: handshakePattern{
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
	//
	//

	NoiseXX: handshakePattern{
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
