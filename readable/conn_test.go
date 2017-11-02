package noise

import "testing"

//
// Should probably have all the tls.conn_test right here
// which I believe test that tls.Conn is first, a correct implementation of net.Conn
// then TLS kind of tests follow
//

func TestNoiseSeveralRoutines(t *testing.T) {

	// init
	clientConfig := Config{
		KeyPair:           GenerateKeypair(),
		HandshakePattern:  NoiseXX,
		PublicKeyVerifier: publicKeyVerifier,
	}
	serverConfig := Config{
		KeyPair:          GenerateKeypair(),
		HandshakePattern: NoiseXX,
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
			_, err2 := serverSocket.Read(buf[:])
			if err2 != nil {
				t.Error("server can't read on socket")
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
