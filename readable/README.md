# NoiseGo

NoiseGo is a protocol based of the [Noise protocol framework](http://noiseprotocol.org/).

## Usage

The same pattern used in [crypto/tls](https://golang.org/pkg/crypto/tls/) can be used to setup a server or a client:

**Server:**

```go
import "github.com/mimoo/NoiseGo/readble/noise"

func main() {
  serverConfig := noise.Config{
    keyPair:          noise.GenerateKeypair(),
    handshakePattern: noise.NoiseNN,
    remoteKey:     []byte{...}
  }

  listener, err := noise.Listen("tcp", "127.0.0.1:0", &serverConfig)
  if err != nil {
    panic("cannot setup a listener on localhost:", err)
  }
  addr := listener.Addr().String()
  fmt.Println("listening on", addr)

  server, err := listener.Accept()
  if err != nil {
    t.Error("a server cannot accept()")
  }

  var buf := make([]byte, 100)

  for {
    _, err := server.Read(buf)
    if err != nil {
      t.Error("server can't read on socket")
    }
    fmt.Println("server received:", string(buf[:n]))
  }
}
```

**Client:**

```go
import "github.com/mimoo/NoiseGo/readble/noise"

func main() {
clientConfig := noise.Config{
  keyPair:           noise.GenerateKeypair(),
  handshakePattern:  noise.NoiseNN,
  remoteKey:     []byte{...}
}

client, err := noise.Dial("tcp", addr, &clientConfig)
if err != nil {
  t.Error("client can't connect to server")
}

_, err = client.Write([]byte("hello"))
if err != nil {
  t.Error("client can't write on socket")
}

```

## documentation

https://godoc.org/github.com/mimoo/NoiseGo/readable


## Todo

* test this with test vectors
* implement Noise into the net.Conn paradigm
* implementing what I'm missing from the spec
