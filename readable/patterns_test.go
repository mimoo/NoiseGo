package noise

import (
	"bytes"
	"testing"
)

func publicKeyVerifier([]byte) bool {
	return true
}

func TestNoiseXX(t *testing.T) {

	// init
	clientConfig := Config{
		keyPair:           GenerateKeypair(),
		handshakePattern:  NoiseXX,
		publicKeyVerifier: publicKeyVerifier,
	}
	serverConfig := Config{
		keyPair:          GenerateKeypair(),
		handshakePattern: NoiseXX,
	}

	// get a Noise.listener
	listener, err := Listen("tcp", "127.0.0.1:0", &serverConfig) // port 0 will find out a free port
	if err != nil {
		t.Error("cannot setup a listener on localhost:", err)
	}
	addr := listener.Addr().String()

	// run the server and Accept one connection
	go func() {
		serverSocket, err := listener.Accept()
		if err != nil {
			t.Error("a server cannot accept()")
		}
		var buf [100]byte
		n, err := serverSocket.Read(buf[:])
		if err != nil {
			t.Error("server can't read on socket")
		}
		if !bytes.Equal(buf[:n], []byte("hello")) {
			t.Error("client message failed")
		}

		if _, err = serverSocket.Write([]byte("ca va?")); err != nil {
			t.Error("server can't write on socket")
		}

	}()

	// Run the client
	clientSocket, err := Dial("tcp", addr, &clientConfig)
	if err != nil {
		t.Error("client can't connect to server")
	}
	_, err = clientSocket.Write([]byte("hello"))
	if err != nil {
		t.Error("client can't write on socket")
	}
	var buf [100]byte
	n, err := clientSocket.Read(buf[:])
	if err != nil {
		t.Error("client can't read server's answer")
	}
	if !bytes.Equal(buf[:n], []byte("ca va?")) {
		t.Error("server message failed")
	}
}

func TestNoiseN(t *testing.T) {

	// init
	serverConfig := Config{
		keyPair:          GenerateKeypair(),
		handshakePattern: NoiseN,
	}

	remoteKey := new(keyPair)
	copy(remoteKey.publicKey[:], serverConfig.keyPair.publicKey[:])
	clientConfig := Config{
		keyPair:          GenerateKeypair(),
		handshakePattern: NoiseN,
		remoteKey:        remoteKey,
	}

	// get a Noise.listener
	listener, err := Listen("tcp", "127.0.0.1:0", &serverConfig) // port 0 will find out a free port
	if err != nil {
		t.Error("cannot setup a listener on localhost:", err)
	}
	addr := listener.Addr().String()

	// run the server and Accept one connection
	go func() {
		serverSocket, err2 := listener.Accept()
		if err2 != nil {
			t.Error("a server cannot accept()")
		}
		var buf [100]byte
		n, err2 := serverSocket.Read(buf[:])
		if err2 != nil {
			t.Error("server can't read on socket")
		}
		if !bytes.Equal(buf[:n], []byte("hello")) {
			t.Error("client message failed")
		}

		/* TODO: test that this fails
		if _, err = serverSocket.Write([]byte("ca va?")); err != nil {
			t.Error("server can't write on socket")
		}
		*/

	}()

	// Run the client
	clientSocket, err := Dial("tcp", addr, &clientConfig)
	if err != nil {
		t.Error("client can't connect to server")
	}
	_, err = clientSocket.Write([]byte("hello"))
	if err != nil {
		t.Error("client can't write on socket")
	}
}
