# Noise Implementation in Go

![disco](http://i.imgur.com/4a9upuk.jpg)

This folder contains two things:

* [readable/](/readable) contains a Noise protocol built in Go from the [Noise Protocol Framework](http://noiseprotocol.org/). It has a minimal set of changes that make it works over UDP and allows you to verify public keys if they were signed by a trusted root key.
* [disco/](/disco) contains an extension of the Noise protocol that makes use of the [Strobe protocol framework](https://www.cryptologie.net/article/416/the-strobe-protocol-framework/). It will most likely move to a different repo at some point.

Note that these two projects are in beta, and you should not use them in production.
