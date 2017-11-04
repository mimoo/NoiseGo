# Noise

The `noise` package contained in this folder is a plug-and-play secure protocol
based on the [Noise protocol framework](http://noiseprotocol.org/). It has been
implemented following the same patterns used in [crypto/tls](https://golang.org/pkg/crypto/tls/).

This has use cases close to TLS: it encrypts communications between a client and a server.

This software is currently in beta.

## documentation

Documentation can be found on [godoc](https://godoc.org/github.com/mimoo/NoiseGo/noise).

Usages can be found in this README.

## Usage

### Installation

Simply get the package:

```bash
$ go get github.com/mimoo/NoiseGo/noise
```

and import it in your application:

```go
package main

import(
  "github.com/mimoo/NoiseGo/noise"
)
```

### Configuration

A `noise.Config` is mandatory. See the [documentation](https://godoc.org/github.com/mimoo/NoiseGo/readable#Config)
to know what are the possible fields.

```
type Config struct {
  HandshakePattern noiseHandshakeType
	KeyPair          *KeyPair
	RemoteKey        *[32]byte
	Prologue         []byte
	StaticPublicKeyProof []byte
	PublicKeyVerifier func(publicKey, proof []byte) bool
	HalfDuplex bool
}
```

**Handshake Pattern**: You will have to choose a *handshake pattern* from [the list of implemented patterns](https://godoc.org/github.com/mimoo/NoiseGo/readable#pkg-constants) first.
The [Noise specification](http://noiseprotocol.org/noise.html#handshake-patterns)
contains more information about this. If something is not clear, or if a pattern
has not been implemented, please use the issues on this repo to tell us.

**KeyPair**: if the *handshake pattern* chosen requires the peer to be initialized
with a static key (because it will send its static key to the other peer during
the handshake), this should be filled with a X25519 `KeyPair` structure.
Several utility functions exist to create and load one, see `GenerateKeypair()`,
`GenerateAndSaveNoiseKeyPair()` and `LoadNoiseKeyPair()`.

**RemoteKey**: if the *handshake pattern* chosen requires the peer to be initialized with the static key of the other peer (because it is supposed to know its peer's static key. Think about **public-key pinning**). This should be a 32-byte X25519 public key.

**Prologue**: any messages that have been exchanged between a client and a server,
prior to the encryption of the channel via Noise, can be authenticated via the *prologue*.
This means that if a man-in-the-middle attacker has removed, added or re-ordered
messages during this phase, the client and the servers will not be able to setup
a secure channel with Noise. To use this, simply concatenate all these messages (on both
the client and the server) and pass them in the prologue value.

**StaticPublicKeyProof**: if the *handshake pattern* chosen has the peer send its
static public key at some point in the handshake, the peer might need to provide
a "proof" that the public key is "legit". For example, the `StaticPublicKeyProof`
can be a signature over the peer's static public key from an authoritative root
key. This "proof" will be sent as part of the handshake, possibly non-encrypted
and visible to passive observers.

**PublicKeyVerifier**: if the *handshake pattern* chosen has the peer receive
a static public key at some point in the handshake, then the peer needs a function
to verify the validity of the received key. During the handshake a "proof" might have
been sent. PublicKeyVerifier is a callback function that must be implemented
by the application using Noise and that will be called on both the static public key
that has been received and any payload that has been received so far. If this function
returns true, the handshake will continue. Otherwise the handshake will fail.

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
    HandshakePattern: noise.Noise_NK,
    KeyPair:          serverKeyPair,
  }

  listener, err := noise.Listen("tcp", "127.0.0.1:6666", &serverConfig)
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

  clientConfig := noise.Config{
    HandshakePattern:  noise.Noise_NK,
    RemoteKey:         []byte{0x01, 0x02, ...}, // replace this with the server's public key
  }

  client, err := noise.Dial("tcp", "127.0.0.0:6666", &clientConfig)
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

## Handshake Patterns Available

Currently, this package does not implement all the defined Noise handshake patterns.
If you are looking for a particular handshake pattern, please use the issues in this repo to request it.

### Noise_NX

This handshake pattern is similar to a typical **browser <-> HTTPS server** scenario where:

* the client does not authenticate itself
* the server authenticates its public key via a signature from an authoritative public key

**Why using this pattern?** If clients talk to several servers, while servers don't expect clients to authenticates themselves.

**Example of configuration**

For this, the **server** needs to be configured with a static public key, as well as a signature over that key


```go
serverConfig := noise.Config{
  HandshakePattern:     noise.Noise_NX,
  KeyPair:              serverKeyPair,
  StaticPublicKeyProof: proof,
}
```

As with our browser <-> HTTPS server scenario, a proof could be an X.509 certificate containing the `serverKeyPair` as well as a signature of the certificate from a certificate authority's public key. But to keep things simple, it could also just be a signature from an authoritative root key.

To help with this, this package comes with utility functions. See the section on the different [Noise keys](#noise-keys).

```go
// CreateStaticPublicKeyProof helps in creating a signature over the peer's static public key
// for that, it needs the private part of a signing root key pair that is trusted by the client.
proof := CreateStaticPublicKeyProof(rootKey.privateKey, peerKeyPair)
```

the **client** needs to be configured with a function capable of acting on the static public key the server will send to it as part of the handshake.
Without this, there are no guarantees that the static public key the server sends is "legit".

```go
clientConfig := noise.Config{
  HandshakePattern:  noise.Noise_NK,
  PublicKeyVerifier: someCallbackFunction,
}
```

Again, the package provides utility functions for this. See the section on the different [Noise keys](#noise-keys).

```go
// CreatePublicKeyVerifier helps in creating a callback function that will verify a signature
// for this it needs the public part of the signing root public key that we trust.
someCallbackFunction := CreatePublicKeyVerifier(rootKey.publicKey)
```

### Noise_XX

The Noise_XX handshake pattern is similar to the previous one, except that both the client and the server authenticates themselves via a static public key.
The proof can be created via the same utility functions and the same root key, or two different root keys. Here is an example of configuration:

**Why using this pattern?** if both the clients and servers talk to different clients and servers, while both needs the other peer to authenticate itself.

**Example of configuration**

server:

```go
// we load the private part of the root signing key
rootPrivateKey, err := noise.LoadNoiseRootPrivateKey("./noiseRootPrivateKeyMama")
if err != nil {
  panic("didn't work")
}
rootPublicKey, err := LoadNoiseRootPublicKey("./noiseRootPublicKeyPapa")
if err != nil {
  panic("didn't work")
}
// we compute our proof over our server's public key (stored in a KeyPair)
proof := noise.CreateStaticPublicKeyProof(rootPrivateKeyMama, serverKeyPair)
// we create our verifier
someCallbackFunction := CreatePublicKeyVerifier(rootPublicKeyPapa)
// we configure the server for Noise_XX
serverConfig := noise.Config{
  HandshakePattern:     noise.Noise_XX,
  KeyPair:              serverKeyPair,
  StaticPublicKeyProof: proof,
  PublicKeyVerifier:    someCallbackFunction,
}
```

client:

```go
// we load the public part of the root signing key
rootPrivateKey, err := noise.LoadNoiseRootPrivateKey("./noiseRootPrivateKeyPapa")
if err != nil {
  panic("didn't work")
}
rootPublicKey, err := LoadNoiseRootPublicKey("./noiseRootPublicKeyMama")
if err != nil {
  panic("didn't work")
}
// we compute our proof over our server's public key (stored in a KeyPair)
proof := noise.CreateStaticPublicKeyProof(rootPrivateKeyPapa, clientKeyPair)
// we create our verifier
someCallbackFunction := CreatePublicKeyVerifier(rootPublicKeyMama)
// we configure the client
clientConfig := noise.Config{
  HandshakePattern:     noise.Noise_XX,
  KeyPair:              clientKeyPair,
  StaticPublicKeyProof: proof,
  PublicKeyVerifier:    someCallbackFunction,
}
```

### Noise_NK

the Noise_NK handshake pattern is similar to mobile device applications connecting to webservers using public-key pinning.

The static public key is hardcoded on the client-side of the connection, because of this it is not "send" by the server during the connection, but still used as part of the cryptographic computations.

**Why using this pattern?** if you already know the server's static key and do not want to rely on an external root signing key and if the server doesn't expect the client to authenticates itself.

**Example of configuration**

server:

```go
serverConfig := noise.Config{
  HandshakePattern: noise.Noise_NK,
  KeyPair:          serverKeyPair,
}
```

client:

```go
clientConfig := noise.Config{
  HandshakePattern: noise.Noise_NK,
  remoteKey:        serverPublicKey, // replace this with the server's public key
}
```

### Noise_KK

The Noise_KK handshake pattern is similar to the Noise_NK pattern, except that both peers are authenticating themselves to each other.

**Why using this pattern?** If the client and the server are always the same two devices (meaning that the server always expect to talk to the same client).

**Example of configuration**

server:

```go
serverConfig := noise.Config{
  HandshakePattern: noise.Noise_KK,
  KeyPair:          serverKeyPair,
  remoteKey:        clientPublicKey, // replace this with the client's public key
}
```

client:

```go
clientConfig := noise.Config{
  HandshakePattern: noise.Noise_KK,
  KeyPair:          clientKeyPair,
  remoteKey:        serverPublicKey, // replace this with the server's public key
}
```

### Noise_N

Noise_N is a one-way handshake pattern. Meaning that only the client can send encrypted data to the server.

**Why using this pattern?** If clients always talk to a single server and the server never talks back to them. The server also doesn't require the client to authenticate itself.

**Example of configuration**

server:

```go
serverConfig := noise.Config{
  HandshakePattern: noise.Noise_N,
  KeyPair:          serverKeyPair,
}
```

client:

```go
clientConfig := noise.Config{
  HandshakePattern: noise.Noise_N,
  remoteKey:        serverPublicKey, // replace this with the server's public key
}
```

## Noise Keys

### The Different Keys

Noise make use of several key pairs:

* Ephemeral keys, they are freshly created for each new client<->server connection.
* Static keys. Each one of the peers, the client and the server, can have their own long-term static key that they will consistently use in handshake patterns that require them (usually a pattern with a K, an X or an I in the name means that the client or/and the server will "make use" (not necessarily send) of a static key as part of the handshake)
* Root signing keys. These are authoritative keys that sign the static keys in patterns where static keys are being "sent" (not just used) as part of the handshake.

### Generation and Storage

**Ephemeral keys** are generated in the code and are never set manually anywhere, for this reason you do not have to worry about these and you can just ignore the fact that they exist.

**Static keys** can be generated via the `GenerateKeypair(nil)` function. They can be constructed from a private key with the same function. The package also provides some file utility functions:

* `KeyPair.ExportPublicKey()` retrieves the public part of a static key pair.
* `GenerateAndSaveNoiseKeyPair()` creates and saves a static key pair on disk.
* `LoadNoiseKeyPair(noisePrivateKeyPairFile()` loads a static key pair from such a file.

**Root signing keys** can be generated via the `GenerateAndSaveNoiseRootKeyPair()` function. As different peers might need different parts, the private and public parts of the key pair will be saved in different files. To retrieve them you can use `LoadNoiseRootPublicKey()` and `LoadNoiseRootPrivateKey()`.

### Configuration of Peers

Imagine a handshake pattern like [Noise_NX](#noise_nx) where only the server sends its static public key.

First let's create the root signing key:

```go
if err := noise.GenerateAndSaveNoiseRootKeyPair("./noiseRootPrivateKey", "./noiseRootPublicKey"); err != nil {
  panic("didn't work")
}
```

Now we can configure the server:

```go
// we load the private part of the root signing key
rootPrivateKey, err := noise.LoadNoiseRootPrivateKey("./noiseRootPrivateKey")
if err != nil {
  panic("didn't work")
}
// we compute our proof over our server's public key (stored in a KeyPair)
proof := noise.CreateStaticPublicKeyProof(rootPrivateKey, serverKeyPair)
// we configure the server for Noise_NX
serverConfig := noise.Config{
  HandshakePattern:     noise.Noise_NX,
  KeyPair:              serverKeyPair,
  StaticPublicKeyProof: proof,
}
```

Once the `noiseRootPublicKey` file has been passed to the client, we can configure it:

```go
// we load the public part of the root signing key
rootPublicKey, err := LoadNoiseRootPublicKey("./noiseRootPublicKey")
if err != nil {
  panic("didn't work")
}
// we create our verifier
someCallbackFunction := CreatePublicKeyVerifier(rootPublicKey)
// we configure the client
clientConfig := noise.Config{
  HandshakePattern:  noise.Noise_NK,
  PublicKeyVerifier: someCallbackFunction,
}
```

And that's it!

## Todo

This code is part of a research project to merge the Noise Protocol Framework with the Disco Protocol Framework. See the [/disco](/disco) folder for more information.

As part of this research, a solid understanding and implementation of Noise is needed.

What follows is an informal roadmap for this code.

Actions that can be taken quickly:

* [~] test this with test vectors
* [x] implement Noise into the net.Conn paradigm
* [ ] good documentation
* [ ] enforce good timeouts (by default `timeout = 0`)
* [ ] polish the code
* [ ] implement [NoiseSocket](http://noisesocket.com/)

These items need more time:

* [ ] implementing pre-shared keys with Argon2?
* [ ] fuzz? (oss-fuzz?)
* [ ] similar library in C
