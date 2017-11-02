# NoiseGo

NoiseGo is a protocol based on the [Noise protocol framework](http://noiseprotocol.org/).

## Usage

The same pattern used in [crypto/tls](https://golang.org/pkg/crypto/tls/) can be used to setup a server or a client:

**Server:**

```go
package main

import(
  "fmt"
  noise "github.com/mimoo/NoiseGo/readble"
)

func main() {
  serverConfig := noise.Config{
    KeyPair:          noise.GenerateKeypair(),
    HandshakePattern: noise.NoiseNK,
  }

  listener, err := noise.Listen("tcp", "127.0.0.1:0", &serverConfig)
  if err != nil {
    panic("cannot setup a listener on localhost:", err)
  }
  addr := listener.Addr().String()
  fmt.Println("listening on", addr)

  server, err := listener.Accept()
  if err != nil {
    t.Error("server cannot accept()")
  }
  defer server.Close()

  var buf := make([]byte, 100)
  for {
    _, err := server.Read(buf)
    if err != nil {
      fmt.Println("server can't read on socket", err)
    }
    fmt.Println("server received some data:", string(buf[:n]))
  }
}
```

**Client:**

```go
package main

import(
  "fmt"
  noise "github.com/mimoo/NoiseGo/readble"
)

func main() {
  clientConfig := noise.Config{
    KeyPair:           noise.GenerateKeypair(),
    HandshakePattern:  noise.NoiseNK,
    RemoteKey:         []byte{0x01, 0x02} // replace this with the server's public key
  }

  client, err := noise.Dial("tcp", addr, &clientConfig)
  if err != nil {
    fmt.Println("client can't connect to server:", err)
    return
  }
  defer client.Close()

  _, err = client.Write([]byte("hello"))
  if err != nil {
    fmt.Println("client can't write on socket:", err)
  }
}
```

## documentation

https://godoc.org/github.com/mimoo/NoiseGo/readable


## Todo

* test this with test vectors
* implement Noise into the net.Conn paradigm
* implementing what I'm missing from the spec
