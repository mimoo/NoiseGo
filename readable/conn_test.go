package noise

import (
	"bytes"
	"testing"
)

//
// Should probably have all the tls.conn_test right here
// which I believe test that tls.Conn is first, a correct implementation of net.Conn
// then TLS kind of tests follow
//

func verifier([]byte, []byte) bool { return true }

func TestNoiseSeveralRoutines(t *testing.T) {

	// init
	clientConfig := Config{
		KeyPair:              GenerateKeypair(),
		HandshakePattern:     Noise_XX,
		StaticPublicKeyProof: []byte{},
		PublicKeyVerifier:    verifier,
	}
	serverConfig := Config{
		KeyPair:              GenerateKeypair(),
		HandshakePattern:     Noise_XX,
		StaticPublicKeyProof: []byte{},
		PublicKeyVerifier:    verifier,
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

		for {
			n, err2 := serverSocket.Read(buf[:])
			if err2 != nil {
				t.Error("server can't read on socket")
			}
			if !bytes.Equal(buf[:n-1], []byte("hello ")) {
				t.Error("received message not as expected")
			}

			//fmt.Println("server received:", string(buf[:n]))
		}

	}()

	// Run the client
	clientSocket, err := Dial("tcp", addr, &clientConfig)
	if err != nil {
		t.Error("client can't connect to server")
	}

	for i := 0; i < 100; i++ {
		go func(i int) {
			message := "hello " + string(i)
			_, err = clientSocket.Write([]byte(message))
			if err != nil {
				t.Error("client can't write on socket")
			}
		}(i)
	}
}
