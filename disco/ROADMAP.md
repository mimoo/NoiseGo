# Roadmap for Disco

A `CONTRIBUTION.md` file should be created after some time. For the moment, this represents an unordered to-do list of things that need to be done:

**Strobe**

Disco relies on a [Strobe implementation in Go](https://github.com/mimoo/StrobeGo/tree/master/compact) which has not been fully tested.

* [ ] make sure that StrobeGo can interact with the reference C code (the reference python code is not up-to-date)
* [ ] setup unit tests for StrobeGo
* [ ] setup test vectors for StrobeGo (if none exist, create some and publish them)
* [ ] setup fuzzing for StrobeGo

**Noise + Disco**

Disco relies on the [Noise protocol framework](http://noiseprotocol.org/), which has not been fully implemented nor tested.

- [ ] Implement Noise's Pre-Shared Key in Disco and NoiseGo.
- [ ] Implement Noise's Other Things (what are they?) in Disco and NoiseGo.
- [~] Test these things in NoiseGo (Test vectors, interact with other libraries, etc...) to make sure the Noise parts are correct
- [x] Implement Noise with Go `net.Conn` interface

**Disco**

- [ ] build a real application on top of Disco
- [ ] Setup fuzzing for Disco.

**More**

- [ ] Test this in different applications. This is important to make sure the API is secure (and easy) to use.
- [ ] Create C and C++ libraries in addition to the Go library.
- [ ] Implement Strobe for other permutations (keccak-f[400] and keccak-f[800])
