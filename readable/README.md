# Noise

The `noise` package contained in this folder is a plug-and-play secure protocol
based on the [Noise protocol framework](http://noiseprotocol.org/). It has been
implemented following the same patterns used in [crypto/tls](https://golang.org/pkg/crypto/tls/).

This has use cases close to TLS: it encrypts communications between a client and a server.

This software is currently in beta.

## documentation

Documentation can be found on [godoc](https://godoc.org/github.com/mimoo/NoiseGo/readable).

Usages can be found in this README.

## Usage

### Installation

Simple get the package

```bash
$ go get github.com/mimoo/NoiseGo/readable
```

and import it in your application. You can also alias it to `noise`:

```go
package main

import(
  noise "github.com/mimoo/NoiseGo/readble"
)
```

### Configuration

A `noise.Config` is mandatory. See the [documentation](https://godoc.org/github.com/mimoo/NoiseGo/readable#Config)
to know what are the possible fields.

**Handshake Pattern**: You will have to choose a *handshake pattern* from [the list of implemented patterns](https://godoc.org/github.com/mimoo/NoiseGo/readable#pkg-constants) first.
The [Noise specification](http://noiseprotocol.org/noise.html#handshake-patterns)
contains more information about this. If something is not clear, or if a pattern
has not been implemented, please use the issues on this repo to tell us.

**Prologue**: any messages that have been exchanged between a client and a server,
prior to the encryption of the channel via Noise, can be authenticated via the *prologue*.
This means that if a man-in-the-middle attacker has removed, added or re-ordered
messages during this phase, the client and the servers will not be able to setup
a secure channel with Noise. To use this, simply concatenate all these messages (on both
the client and the server) and pass them in the prologue value.

**KeyPair**: if the *handshake pattern* chosen requires the peer to be initialized
with a static key (because it will send its static key to the other peer during
the handshake), this should be filled with a X25519 `KeyPair` structure.
Several utility functions exist to create and load one, see `GenerateKeypair()`,
`GenerateAndSaveNoiseKeyPair()` and `LoadNoiseKeyPair()`.

**RemoteKeyPair**: if the *handshake pattern* chosen requires the peer to be initialized
with the static key of the other peer (because it is supposed to know its peer's
static key. Think about **public-key pinning**). Then this should be filled with a
X25519 `KeyPair` as well.

**PublicKeyVerifier**: if the *handshake pattern* chosen has the peer receive
a static public key at some point in the handshake, then the peer needs a function
to verify the validity of the received key. During the handshake a "proof" might have
been sent. PublicKeyVerifier is a callback function that must be implemented
by the application using Noise and that will be called on both the static public key
that has been received and any payload that has been received so far. If this function
returns true, the handshake will continue. Otherwise the handshake will fail.

**StaticPublicKeyProof**: if the *handshake pattern* chosen has the peer send its
static public key at some point in the handshake, the peer might need to provide
a "proof" that the public key is "legit". For example, the `StaticPublicKeyProof`
can be a signature over the peer's static public key from an authoritative root
key. This "proof" will be sent as part of the handshake, possibly non-encrypted
and visible to passive observers.

**HalfDuplex**: In some situation, one of the peer might be constrained by the
size of its memory. In such scenarios, communication over a single writing channel
might be a solution. Noise provides half-duplex channels where the client and the
server take turn to write or read on the secure channel.

### Server

Simply use the `Listen()` and `Accept()` paradigm. You then get
an object implementing the [net.Conn](https://golang.org/pkg/net/#Conn) interface.
You can then `Write()` and `Read()`.

The following example use the `Noise_NK` handshake where the client is not authenticated
and the server's key is known to the client in advance.

```go
package main

import(
  "fmt"
  noise "github.com/mimoo/NoiseGo/readble"
)

func main() {

  serverKeyPair := noise.GenerateKeypair()

  serverConfig := noise.Config{
    KeyPair:          serverKeyPair,
    HandshakePattern: noise.Noise_NK,
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

### Client

The client can simply use the `Dial()` paradigm:

```go
package main

import(
  "fmt"
  noise "github.com/mimoo/NoiseGo/readble"
)

func main() {
  var serverKey KeyPair
  serverKey.publicKey = []byte{0x01, 0x02, ...} // replace this with the server's public key
  clientConfig := noise.Config{
    HandshakePattern:  noise.Noise_NK,
    RemoteKey:         serverKey,
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


## Todo

* [~] test this with test vectors
* [x] implement Noise into the net.Conn paradigm
* [ ] good documentation
* [ ] enforce good timeouts (by default `timeout = 0`)
* [ ] implementing pre-shared keys with Argon2?
* [ ] polish the code
* [ ] fuzz? (oss-fuzz?)
* [ ] similar library in C
