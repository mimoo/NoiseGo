# Noise Implementation in Go

![disco](http://i.imgur.com/4a9upuk.jpg)

This is a **readable** implementation of the [Noise Protocol Framework](http://noiseprotocol.org/).

I have tried to respect the Noise specification as much as possible.

Note that this is highly experimental and it has not been thoroughly tested.

I also had to deviate from the specification when naming things because Golang:

* doesn't use snake_case, but Noise does.
* capitalizes function names to make them public, Noise does it for different reasons.

At the moment this repository also contains an experimental merge of Noise and Strobe called Disco. [Check the /disco folder](/disco).
