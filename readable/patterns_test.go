package noise

import (
	"bytes"
	"testing"
)

func publicKeyVerifier([]byte) bool {
	return true
}

func TestNoiseKK(t *testing.T) {

	// init
	clientConfig := Config{
		KeyPair:          GenerateKeypair(),
		HandshakePattern: Noise_KK,
	}
	serverConfig := Config{
		KeyPair:          GenerateKeypair(),
		HandshakePattern: Noise_KK,
	}

	// set up remote keys
	remoteKeyClient := new(keyPair)
	copy(remoteKeyClient.publicKey[:], clientConfig.KeyPair.publicKey[:])
	serverConfig.RemoteKey = remoteKeyClient

	remoteKeyServer := new(keyPair)
	copy(remoteKeyServer.publicKey[:], serverConfig.KeyPair.publicKey[:])
	clientConfig.RemoteKey = remoteKeyServer

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
		t.Error("client can't connect to server", err)
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

func TestNoiseNK(t *testing.T) {

	test_pattern := Noise_NK

	// init
	clientConfig := Config{
		KeyPair:          GenerateKeypair(),
		HandshakePattern: test_pattern,
	}
	serverConfig := Config{
		KeyPair:          GenerateKeypair(),
		HandshakePattern: test_pattern,
	}

	// setup remote key
	remoteKeyServer := new(keyPair)
	copy(remoteKeyServer.publicKey[:], serverConfig.KeyPair.publicKey[:])
	clientConfig.RemoteKey = remoteKeyServer

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
		t.Error("client can't connect to server", err)
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

func TestNoiseXX(t *testing.T) {

	// init
	clientConfig := Config{
		KeyPair:           GenerateKeypair(),
		HandshakePattern:  Noise_XX,
		PublicKeyVerifier: publicKeyVerifier,
	}
	serverConfig := Config{
		KeyPair:          GenerateKeypair(),
		HandshakePattern: Noise_XX,
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
		t.Error("client can't connect to server", err)
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
		KeyPair:          GenerateKeypair(),
		HandshakePattern: Noise_N,
	}

	remoteKey := new(keyPair)
	copy(remoteKey.publicKey[:], serverConfig.KeyPair.publicKey[:])

	clientConfig := Config{
		KeyPair:          GenerateKeypair(),
		HandshakePattern: Noise_N,
		RemoteKey:        remoteKey,
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
