---
title:      'The Disco Protocol Framework'
author:     'David Wong (moi@davidwong.fr), Trevor Perrin (noise@trevp.net)'
revision:   '1'
date:       '2017-06-17'
bibliography: 'my.bib'
link-citations: 'true'
csl:        'ieee-with-url.csl'
---

1. Introduction
================

Disco is a framework for crypto protocols based on the Disco Protocol framework
and the Strobe protocol framework. Disco can describe protocols that consist of
a single message as well as interactive protocols.  

2. Overview
============

2.1. Terminology
-----------------

A Disco protocol begins with two parties exchanging **handshake messages**.
During this **handshake phase** the parties exchange DH public keys and perform
a sequence of DH operations, hashing the DH results into a shared secret key.
After the handshake phase each party can use this shared key to send encrypted
**transport messages**.

The Disco framework supports handshakes where each party has a long-term
**static key pair** and/or an **ephemeral key pair**.  A Disco handshake is
described by a simple language.  This language consists of **tokens** which are
arranged into **message patterns**.  Message patterns are arranged into
**handshake patterns**.

A **message pattern** is a sequence of tokens that specifies the DH public keys
that comprise a handshake message, and the DH operations that are performed
when sending or receiving that message.  A **handshake pattern** specifies the
sequential exchange of messages that comprise a handshake.

A handshake pattern can be instantiated by **DH functions** and **Strobe
functions** to give a concrete **Disco protocol**.

2.2. Overview of handshake state machine
-----------------------------------------

The core of Disco is a set of variables maintained by each party during a
handshake, and rules for sending and receiving handshake messages by
sequentially processing the tokens from a message pattern.

Each party maintains the following variables:

 * **`s, e`**: The local party's static and ephemeral key pairs (which may be
   empty).

 * **`rs, re`**: The remote party's static and ephemeral public keys (which may
   be empty).

 * **`StrobeState`**: A **StrobeState** object that absorbs all the handshake
   data that's been sent and received. It is also used to encrypt
   static public keys and handshake payloads, which provides confidentiality
   and key confirmation during the handshake phase. Encryption uses some
   **AEAD** cipher mode (in the sense of Rogaway [@Rogaway:2002]) and
   continuously depends on all previous sent and received messages.
   Once the handshake completes, the Strobe state will be used
   to derive two other Strobe state for transport messages.

A handshake message consists of some DH public keys followed by a **payload**.
The payload may contain certificates or other data chosen by the application.
To send a handshake message, the sender specifies the payload and sequentially
processes each token from a message pattern.  The possible tokens are:

 * **`"e"`**: The sender generates a new ephemeral key pair and stores it in
   the `e` variable, writes the ephemeral public key as cleartext into the
   message buffer, and pass it through the Strobe state for absorbtion.

 * **`"s"`**: The sender writes its static public key from the `s` variable
   into the message buffer, encrypting it (effectively if the Strobe state has
   been keyed by a Diffie-Hellman key exchange).

 * **`"ee", "se", "es", "ss"`**: A DH is performed between the initiator's key
   pair (whether static or ephemeral is determined by the first letter) and the
   responder's key pair (whether static or ephemeral is determined by the
   second letter).  The result is used to key the Strobe state.

After processing the final token in a handshake message, the sender then writes
the payload into the message buffer, encrypting it (effectively if the Strobe
state has been keyed), and absorbs it in the Strobe state.

As a simple example, an unauthenticated DH handshake is described by the
handshake pattern:

      -> e
      <- e, ee

The **initiator** sends the first message, which is simply an ephemeral public key.
The **responder** sends back its own ephemeral public key.  Then a DH is performed
and the output is hashed into a shared secret key.

Note that a cleartext payload is sent in the first message, after the cleartext
ephemeral public key, and an encrypted payload is sent in the response message,
after the cleartext ephemeral public key.  The application may send whatever
payloads it wants.

The responder can send its static public key (under encryption) and
authenticate itself via a slightly different pattern:

      -> e
      <- e, ee, s, es

In this case, the final Strobe state depends on both DH results.
Since the `es` token indicates a DH between the initiator's ephemeral key and
the responder's static key, successful decryption by the initiator of the
second message's payload serves to authenticate the responder to the initiator.

Note that the second message's payload may contain a zero-length plaintext, but
the payload ciphertext will still contain authentication data (such as an
authentication tag or "synthetic IV"), since encryption is with an AEAD mode.
The second message's payload can also be used to deliver certificates for the
responder's static public key.

The initiator can send *its* static public key (under encryption), and
authenticate itself, using a handshake pattern with one additional message:

      -> e
      <- e, ee, s, es
      -> s, se

The following sections flesh out the details, and add some complications.
However, the core of Disco is this simple system of variables, tokens, and
processing rules, which allow concise expression of a range of protocols.

3.  Message format
===================

All Disco messages are less than or equal to 65535 bytes in length.
Restricting message size has several advantages:

 * Simpler testing, since it's easy to test the maximum sizes.

 * Reduces the likelihood of errors in memory handling, or integer overflow.

 * Enables support for streaming decryption and random-access decryption of
   large data streams.

 * Enables higher-level protocols that encapsulate Disco messages to use an efficient
 standard length field of 16 bits.

All Disco messages can be processed without parsing, since there are no type or
length fields.  Of course, Disco messages might be encapsulated within a
higher-level protocol that contains type and length information.  Disco
messages might encapsulate payloads that require parsing of some sort, but
payloads are handled by the application, not by Disco.

A Disco **transport message** is simply an AEAD ciphertext that is less than or
equal to 65535 bytes in length, and that consists of an encrypted payload plus
16 bytes of authentication data.

A Disco **handshake message** is also less than or equal to 65535 bytes.  It
begins with a sequence of one or more DH public keys, as determined by its
message pattern.  Following the public keys will be a single payload which can
be used to convey certificates or other handshake data, but can also contain a
zero-length plaintext.

Static public keys and payloads will be in cleartext if they are sent in a
handshake prior to a DH operation, and will be AEAD ciphertexts if they occur
after a DH operation.  (If Disco is being used with pre-shared symmetric keys,
this rule is different; see [Section 9](#pre-shared-symmetric-keys)).  Like transport messages, AEAD
ciphertexts will expand each encrypted field (whether static public key or
payload) by 16 bytes.

For an example, consider the handshake pattern:

      -> e
      <- e, ee, s, es
      -> s, se

The first message consists of a cleartext public key (`"e"`) followed by a
cleartext payload (remember that a payload is implicit at the end of each
message pattern).  The second message consists of a cleartext public key
(`"e"`) followed by an encrypted public key (`"s"`) followed by an encrypted
payload.  The third message consists of an encrypted public key (`"s"`)
followed by an encrypted payload.  

Assuming each payload contains a zero-length plaintext, and DH public keys are
56 bytes, the message sizes will be:

  1. 56 bytes (one cleartext public key and a cleartext payload)
  2. 144 bytes (two public keys, the second encrypted, and encrypted payload)
  3. 88 bytes (one encrypted public key and encrypted payload)

&nbsp;

4. Crypto functions
=====================

A Disco protocol is instantiated with a concrete set of **DH functions** and
**Strobe functions**.  The signature for these
functions is defined below.  Some concrete functions are defined in [Section
12](#dh-functions-cipher-functions-and-hash-functions).

The following notation will be used in algorithm pseudocode:

 * The `||` operator concatenates byte sequences.
 * The `byte()` function constructs a single byte.

4.1. DH functions
------------------

Disco depends on the following **DH functions** (and an associated constant):

 * **`GENERATE_KEYPAIR()`**: Generates a new Diffie-Hellman key pair.  A DH key pair
   consists of `public_key` and `private_key` elements.  A `public_key`
   represents an encoding of a DH public key into a byte sequence of
   length `DHLEN`.  The `public_key` encoding details are specific to each set
   of DH functions.

 * **`DH(key_pair, public_key)`**: Performs a Diffie-Hellman calculation
   between the private key in `key_pair` and the `public_key` and returns an output
   sequence of bytes of length `DHLEN`.  For security, the Gap-DH problem based
   on this function must be unsolvable by any practical cryptanalytic adversary
   [@gapdh].  

     The `public_key` either encodes some value in a large prime-order group
     (which may have multiple equivalent encodings), or is an invalid value.
     Implementations must handle invalid public keys either by returning some
     output which is purely a function of the public key and does not depend on
     the private key, or by signaling an error to the caller.  The DH function
     may define more specific rules for handling invalid values.

 * **`DHLEN`** = A constant specifying the size in bytes of public keys and DH
   outputs.  For security reasons, `DHLEN` must be 32 or greater.


5. Processing rules
====================

To precisely define the processing rules we adopt an object-oriented
terminology, and present one "object" which encapsulate state variables and
contain functions which implement processing logic.

A **`HandshakeState`** object contains a `StrobeState` plus DH variables
`(s, e, rs, re)` and a variable representing the handshake pattern.
During the handshake phase each party has a single `HandshakeState`, which
can be deleted once the handshake is finished.

To execute a Disco protocol you `Initialize()` a `HandshakeState`.  During
initialization you specify the handshake pattern, any local key pairs, and any
public keys for the remote party you have knowledge of.  After `Initialize()`
you call `WriteMessage()` and `ReadMessage()` on the `HandshakeState` to
process each handshake message.  If any error is signaled the handshake has
failed and the `HandshakeState` is deleted.

Processing the final handshake message returns two `StrobeState` objects, the
first for encrypting transport messages from initiator to responder, and the
second for messages in the other direction.  At that point the `HandshakeState`
should be deleted.

Transport messages are then encrypted and decrypted by calling
`SEND_AEAD()` and `RECV_AEAD()` on the relevant `StrobeState` with
zero-length associated data.  If `RECV_AEAD()` signals an error due to
a MAC failure, then the output is discarded and application must delete
the `StrobeState` and terminate the session.


5.1. StrobeState object
-----------------------

A StrobeState, implemented according to the Strobe specification [@strobe],
responds to the following functions:

 * **`InitializeStrobe(protocol_name)`**: Initialize the Strobe object with
   a custom protocol name.

 * **`KEY(key)`**:
   Replaces the Strobe's state with the key.

 * **`PRF(output_len)`**:
   Removes `output_len` bytes from the Strobe's state and outputs them to the
   caller.

 * **`Send_ENC(plaintext)`**:
   XOR the plaintext with the Strobe's state. The Strobe's state is replaced by
   the resulting ciphertext. This outputs the ciphertext to the caller as well.

 * **`Recv_ENC(ciphertext)`**:
   XOR the ciphertext with the Strobe's state. The Strobe's state is replaced
   by the ciphertext, while the resulting plaintext is output to the caller.

 * **`AD(additionalData)`**:
   XOR the additional data in the Strobe's state.

 * **`Send_CLR(cleartext)`**:
   XOR the cleartext in the Strobe's state.

 * **`Recv_CLR(cleartext)`**:
   XOR the cleartext in the Strobe's state.

 * **`Send_MAC(output_length)`**:
   Retrieves the next `output_length` bytes from the Strobe's state.

 * **`Recv_MAC(tag)`**:
   Compare in constant-time the received tag with the next `len(tag)` bytes
   from the Strobe's state.

 * **`Send_AEAD(plaintext, ad)`**:
   Combines `SEND_ENC` followed with `SEND_MAC(TAGLEN)`.

 * **`Recv_AEAD(ciphertext, ad)`**:
   Combines `RECV_ENC` followed with `RECV_MAC(TAGLEN)`.

 * **`RATCHET(length)`**:
   Set the next `length` bytes from the Strobe's state to zero.

 * **`TAGLEN`** = A constant specifying the size in bytes of the message
   Authentication Codes generated by `SEND_AEAD` or `SEND_MAC`.
   For security reasons, `DHLEN` must be 16 or greater.


5.2. The `HandshakeState` object
---------------------------------

A `HandshakeState` object contains a `StrobeState` plus the following
variables, any of which may be `empty`.  `Empty` is a special value which
indicates the variable has not yet been initialized.

  * **`s`**: The local static key pair
  * **`e`**: The local ephemeral key pair
  * **`rs`**: The remote party's static public key
  * **`re`**: The remote party's ephemeral public key

A `HandshakeState` also has variables to track its role, and the remaining
portion of the handshake pattern:

  * **`initiator`**: A boolean indicating the initiator or responder role.

  * **`message_patterns`**: A sequence of message patterns.  Each message
    pattern is a sequence of tokens from the set `("e", "s", "ee", "es", "se",
    "ss")`.  (An additional `"psk"` token is introduced in [Section
    9](pre-shared-symmetric-keys), but we defer its explanation until then.)

A `HandshakeState` responds to the following functions:

  * **`Initialize(handshake_pattern, initiator, prologue, s, e, rs, re)`**:
    Takes a valid `handshake_pattern` (see [Section 7](#handshake-patterns)) and an
    `initiator` boolean specifying this party's role as either initiator or
    responder.  

    Takes a `prologue` byte sequence which may be zero-length, or
    which may contain context information that both parties want to confirm is
    identical (see [Section 6](#prologue)).  

    Takes a set of DH key pairs `(s, e)` and
    public keys `(rs, re)` for initializing local variables, any of which may be empty.
    Public keys are only passed in if the `handshake_pattern` uses pre-messages
    (see [Section 7](#handshake-patterns)).  The ephemeral values `(e, re)` are typically
    left empty, since they are created and exchanged during the handshake; but there are
    exceptions (see [Section 10.1](fallback-patterns)).

    Performs the following steps:

      * Derives a `protocol_name` byte sequence by combining the names for the
        handshake pattern and crypto functions, as specified in [Section
        8](#protocol-names). Calls `InitializeStrobe(protocol_name)`.

      * Calls `AD(prologue)`.

      * Sets the `initiator`, `s`, `e`, `rs`, and `re` variables to the
        corresponding arguments.

      * Calls `AD()` once for each public key listed in the pre-messages
        from `handshake_pattern`, with the specified public key as input (see
        [Section 7](#handshake-patterns) for an explanation of pre-messages).  If both
        initiator and responder have pre-messages, the initiator's public keys
        are hashed first.

      * Sets `message_patterns` to the message patterns from `handshake_pattern`.

  * **`WriteMessage(payload, message_buffer)`**: Takes a `payload` byte sequence
   which may be zero-length, and a `message_buffer` to write the output into.  Performs the following steps:

      * Fetches and deletes the next message pattern from `message_patterns`,
        then sequentially processes each token from the message pattern:

          * For `"e"`:  Sets `e = GENERATE_KEYPAIR()`.  Appends `e.public_key`
            to the buffer.  Calls `AD(e.public_key)`.

          * For `"s"`:  Appends `SEND_AEAD(s.public_key)` to the buffer.  

          * For `"ee"`: Calls `AD(DH(e, re))`.

          * For `"es"`: Calls `AD(DH(e, rs))` if initiator, `AD(DH(s, re))` if responder.

          * For `"se"`: Calls `AD(DH(s, re))` if initiator, `AD(DH(e, rs))` if responder.

          * For `"ss"`: Calls `AD(DH(s, rs))`.

      * Appends `SEND_ENC(payload)` to the buffer.  

      * If there are no more message patterns returns two new `StrobeState`
        objects by calling `Split()`.

\newpage

  * **`ReadMessage(message, payload_buffer)`**: Takes a byte sequence
    containing a Disco handshake message, and a `payload_buffer` to write the
    message's plaintext payload into.  Performs the following steps:

      * Fetches and deletes the next message pattern from `message_patterns`,
        then sequentially processes each token from the message pattern:

          * For `"e"`: Sets `re` to the next `DHLEN` bytes from the message.
            Calls `AD(re.public_key)`.

          * For `"s"`: Sets `temp` to the next `DHLEN + 16` bytes of the message.
            Sets `rs` to `Recv_AEAD(temp)`.  

          * For `"ee"`: Calls `AD(DH(e, re))`.

          * For `"es"`: Calls `AD(DH(e, rs))` if initiator, `AD(DH(s, re))` if responder.

          * For `"se"`: Calls `AD(DH(s, re))` if initiator, `AD(DH(e, rs))` if responder.

          * For `"ss"`: Calls `AD(DH(s, rs))`.

      * Calls `Recv_AEAD()` on the remaining bytes of the message and stores
        the output into `payload_buffer`.

      * If there are no more message patterns returns two new `StrobeState`
        objects by calling `Split()`.

 * **`Split()`**:
   Returns a pair of StrobeState objects for encrypting transport messages.
   Executes the following steps:

    * Sets `s1 = StrobeState` and `s2 = Clone(StrobeState)`.

    * Calls `KEY("initiator")` with `s1` and `KEY("responder")` with `s2`.

    * Returns the pair (`s1`, `s2`).

 * **`Clone(strobe_state)`**: Returns a copy of the `strobe_state`.


6. Prologue
============

Disco protocols have a **prologue** input which allows arbitrary data to be
hashed into the `h` variable.  If both parties do not provide identical
prologue data, the handshake will fail due to a decryption error.  This is
useful when the parties engaged in negotiation prior to the handshake and want
to ensure they share identical views of that negotiation.  

For example, suppose Bob communicates to Alice a list of Disco protocols that
he is willing to support.  Alice will then choose and execute a single
protocol.  To ensure that a "man-in-the-middle" did not edit Bob's list to
remove options, Alice and Bob could include the list as prologue data.

Note that while the parties confirm their prologues are identical, they don't
mix prologue data into encryption keys. If an input contains secret data that’s
intended to strengthen the encryption, a PSK handshake should be used
instead (see [Section 9](pre-shared-symmetric-keys)).  


7. Handshake patterns
======================

A **message pattern** is some sequence of tokens from the set `("e", "s", "ee",
"es", "se", "ss", "psk")`.  (The `"psk"` token is described in [Section
9](pre-shared-symmetric-keys); future specifications might introduce other
tokens).

A **pre-message pattern** is one of the following sequences of tokens:

  * `"e"`
  * `"s"`
  * `"e, s"`
  * empty


A **handshake pattern** consists of:

  * A pre-message pattern for the initiator, representing information about
  the initiator's public keys that is known to the responder.

  * A pre-message pattern for the responder, representing information about the
  responder's public keys that is known to the initiator.

  * A sequence of message patterns for the actual handshake messages

The pre-messages represent an exchange of public keys that was somehow
performed prior to the handshake, so these public keys must be inputs to
`Initialize()` for the "recipient" of the pre-message.  

The first actual handshake message is sent from the initiator to the responder
(with one exception - see next paragraph).  The next message is sent by the
responder, the next from the initiator, and so on in alternating fashion.

(Exceptional case: Disco allows special **fallback patterns** where the
responder switches to a different pattern than the initator started with (see
[Section 10.1](#fallback-patterns)).  If the initiator's pre-message contains an
`"e"` token, then this handshake pattern is a fallback pattern.  In the case of
a fallback pattern the first handshake message is sent by the *responder*,
the next by the *initiator*, and so on.)

The following handshake pattern describes an unauthenticated DH handshake:

    Disco_NN():
      -> e
      <- e, ee

The handshake pattern name is `Disco_NN`.  This naming convention will be
explained in [Section 7.3](#interactive-patterns).  The empty parentheses
indicate that neither party is initialized with any key pairs.  The tokens
`"s"`, `"e"`, or `"e, s"` inside the parentheses would indicate that the
initiator is initialized with static and/or ephemeral key pairs.  The tokens
`"rs"`, `"re"`, or `"re, rs"` would indicate the same thing for the responder.

Right-pointing arrows show messages sent by the initiator.  Left-pointing
arrows show messages sent by the responder.

Non-empty pre-messages are shown as patterns prior to the delimiter "...", with a
right-pointing arrow for the initiator's pre-message, and a left-pointing arrow
for the responder's pre-message.  If both parties have a pre-message, the
initiator's is listed first (and hashed first).  During `Initialize()`,
`AD()` is called on any pre-message public keys, as described in [Section
5.3](#the-handshakestate-object).

The following pattern describes a handshake where the initiator has
pre-knowledge of the responder's static public key, and performs a DH with the
responder's static public key as well as the responder's ephemeral public key.
This pre-knowledge allows an encrypted payload to be sent in the first message
("zero-RTT encryption"), although full forward secrecy and replay protection is
only achieved with the second message.

    Disco_NK(rs):
      <- s
      ...
      -> e, es
      <- e, ee

7.1. Pattern validity
----------------------

Handshake patterns must be **valid** in the following senses:

 1. Parties can only send a static public key if they were initialized with a
   static key pair, and can only perform DH between private keys and public
   keys they possess.

 2. Parties must not send their static public key, or an ephemeral public key,
    more than once per handshake (i.e. including the pre-messages, there must be
    no more than one occurrence of "e", and one occurrence of "s", in the
    messages sent by any party).

 3. After performing a DH between a remote public key and any local private key
    that is not an ephemeral private key, the local party must not send any
    encrypted data unless it has also
    performed a DH between an ephemeral private key and the remote public key.  

Patterns failing the first check are obviously nonsense.

The second check outlaws redundant transmission of values to simplify
implementation and testing.

The third check is necessary because Disco uses DH outputs
involving ephemeral keys to randomize the shared secret keys.  Patterns failing
this check could result in subtle but catastrophic security flaws.  

Users are recommended to only use the handshake patterns listed below, or other
patterns that have been vetted by experts to satisfy the above checks.

\newpage

7.2. One-way patterns
----------------------

The following example handshake patterns represent "one-way" handshakes
supporting a one-way stream of data from a sender to a recipient.  These
patterns could be used to encrypt files, database records, or other
non-interactive data streams.

Following a one-way handshake the sender can send a stream of transport
messages, encrypting them using the first `StrobeState` returned by `Split()`.
The second `StrobeState` from `Split()` is discarded - the recipient must not
send any messages using it (as this would violate the rules in [Section 7.1](#pattern-validity)).

One-way patterns are named with a single character, which indicates the
status of the sender's static key:

 * **`N`** = **`N`**o static key for sender
 * **`K`** = Static key for sender **`K`**nown to recipient
 * **`X`** = Static key for sender **`X`**mitted ("transmitted") to recipient

+-------------------------+
|     Disco_N(rs):        |
|       <- s              |
|       ...               |
|       -> e, es          |
+-------------------------+
|     Disco_K(s, rs):     |
|       -> s              |
|       <- s              |
|       ...               |
|       -> e, es, ss      |
+-------------------------+
|     Disco_X(s, rs):     |
|       <- s              |
|       ...               |
|       -> e, es, s, ss   |
+-------------------------+

`Disco_N` is a conventional DH-based public-key encryption.  The other patterns
add sender authentication, where the sender's public key is either known to the
recipient beforehand (`Disco_K`) or transmitted under encryption (`Disco_X`).

7.3. Interactive patterns
--------------------------

The following example handshake patterns represent interactive protocols.

Interactive patterns are named with two characters, which indicate the
status of the initator and responder's static keys:

The first character refers to the initiator's static key:

 * **`N`** = **`N`**o static key for initiator
 * **`K`** = Static key for initiator **`K`**nown to responder
 * **`X`** = Static key for initiator **`X`**mitted ("transmitted") to responder
 * **`I`** = Static key for initiator **`I`**mmediately transmitted to responder,
 despite reduced or absent identity hiding

The second character refers to the responder's static key:

 * **`N`** = **`N`**o static key for responder
 * **`K`** = Static key for responder **`K`**nown to initiator
 * **`X`** = Static key for responder **`X`**mitted ("transmitted") to initiator

\newpage

+---------------------------+--------------------------------+
|     Disco_NN():           |        Disco_KN(s):            |
|       -> e                |          -> s                  |
|       <- e, ee            |          ...                   |
|                           |          -> e                  |
|                           |          <- e, ee, se          |
+---------------------------+--------------------------------+
|     Disco_NK(rs):         |        Disco_KK(s, rs):        |
|       <- s                |          -> s                  |
|       ...                 |          <- s                  |
|       -> e, es            |          ...                   |
|       <- e, ee            |          -> e, es, ss          |
|                           |          <- e, ee, se          |
+---------------------------+--------------------------------+
|      Disco_NX(rs):        |         Disco_KX(s, rs):       |
|        -> e               |           -> s                 |
|        <- e, ee, s, es    |           ...                  |
|                           |           -> e                 |
|                           |           <- e, ee, se, s, es  |
+---------------------------+--------------------------------+
|      Disco_XN(s):         |         Disco_IN(s):           |
|        -> e               |           -> e, s              |
|        <- e, ee           |           <- e, ee, se         |
|        -> s, se           |                                |
+---------------------------+--------------------------------+
|      Disco_XK(s, rs):     |         Disco_IK(s, rs):       |
|        <- s               |           <- s                 |      
|        ...                |           ...                  |
|        -> e, es           |           -> e, es, s, ss      |
|        <- e, ee           |           <- e, ee, se         |
|        -> s, se           |                                |
+---------------------------+--------------------------------+
|      Disco_XX(s, rs):     |         Disco_IX(s, rs):       |
|        -> e               |           -> e, s              |
|        <- e, ee, s, es    |           <- e, ee, se, s, es  |
|        -> s, se           |                                |
+---------------------------+--------------------------------+

\newpage

The `Disco_XX` pattern is the most generically useful, since it is efficient
and supports mutual authentication and transmission of static public keys.

All interactive patterns allow some encryption of handshake payloads:

 * Patterns where the initiator has pre-knowledge of the responder's static
   public key (i.e. patterns ending in `"K"`) allow **zero-RTT** encryption,
   meaning the initiator can encrypt the first handshake payload.  

 * All interactive patterns allow **half-RTT** encryption of the first response
   payload, but the encryption only targets an initiator static public key in
   patterns starting with "K" or "I".

The security properties for handshake payloads are usually weaker than the
final security properties achieved by transport payloads, so these early
encryptions must be used with caution.



In some patterns the security properties of transport payloads can also vary.
In particular: patterns starting with "K" or "I" have the caveat that the
responder is only guaranteed "weak" forward secrecy for the transport messages
it sends until it receives a transport message from the initiator.  After
receiving a transport message from the initiator, the responder becomes assured
of "strong" forward secrecy.

The next section provides more analysis of these payload security properties.

7.4. Payload security properties
---------------------------------

The following table lists the security properties for Disco handshake and
transport payloads for all the named patterns in [Section 7.2](#one-way-patterns) and
[Section 7.3](#interactive-patterns).  Each payload is assigned an "authentication"
property regarding the degree of authentication of the sender provided to the
recipient, and a "confidentiality" property regarding the degree of
confidentiality provided to the sender.

The authentication properties are:

 0. **No authentication.**  This payload may have been sent by any party,
    including an active attacker.

 1. **Sender authentication *vulnerable* to key-compromise impersonation
    (KCI)**.  The sender authentication is based on a static-static DH
    (`"ss"`) involving both parties' static key pairs.  If the recipient's
    long-term private key has been compromised, this authentication can be
    forged.  Note that a future version of Disco might include signatures,
    which could improve this security property, but brings other trade-offs.

 2. **Sender authentication *resistant* to key-compromise impersonation
    (KCI)**.  The sender authentication is based on an ephemeral-static DH
    (`"es"` or `"se"`) between the sender's static key pair and the
    recipient's ephemeral key pair.  Assuming the corresponding private keys
    are secure, this authentication cannot be forged.

The confidentiality properties are:

 0. **No confidentiality.**  This payload is sent in cleartext.

 1. **Encryption to an ephemeral recipient.**  This payload has forward
    secrecy, since encryption involves an ephemeral-ephemeral DH (`"ee"`).
    However, the sender has not authenticated the recipient, so this payload
    might be sent to any party, including an active attacker.

 2. **Encryption to a known recipient, forward secrecy for sender
    compromise only, vulnerable to replay.** This payload is encrypted based
    only on DHs involving the recipient's static key pair.  If the recipient's
    static private key is compromised, even at a later date, this payload can
    be decrypted.  This message can also be replayed, since there's no
    ephemeral contribution from the recipient.

 3. **Encryption to a known recipient, weak forward secrecy.**  This
    payload is encrypted based on an ephemeral-ephemeral DH and also an
    ephemeral-static DH involving the recipient's static key pair.  However,
    the binding between the recipient's alleged ephemeral public key and the
    recipient's static public key hasn't been verified by the sender, so the
    recipient's alleged ephemeral public key may have been forged by an active
    attacker.  In this case, the attacker could later compromise the
    recipient's static private key to decrypt the payload. Note that a future
    version of Disco might include signatures, which could improve this
    security property, but brings other trade-offs.

 4. **Encryption to a known recipient, weak forward secrecy if the
    sender's private key has been compromised.**  This payload is encrypted
    based on an ephemeral-ephemeral DH, and also based on an ephemeral-static
    DH involving the recipient's static key pair.  However, the binding
    between the recipient's alleged ephemeral public and the recipient's
    static public key has only been verified based on DHs involving both those
    public keys and the sender's static private key.  Thus, if the sender's
    static private key was previously compromised, the recipient's alleged
    ephemeral public key may have been forged by an active attacker.  In this
    case, the attacker could later compromise the intended recipient's static
    private key to decrypt the payload (this is a variant of a "KCI" attack
    enabling a "weak forward secrecy" attack). Note that a future version of
    Disco might include signatures, which could improve this security
    property, but brings other trade-offs.

 5. **Encryption to a known recipient, strong forward secrecy.**  This
    payload is encrypted based on an ephemeral-ephemeral DH as well as an
    ephemeral-static DH with the recipient's static key pair.  Assuming the
    ephemeral private keys are secure, and the recipient is not being actively
    impersonated by an attacker that has stolen its static private key, this
    payload cannot be decrypted.

For one-way handshakes, the below-listed security properties apply to the
handshake payload as well as transport payloads.

For interactive handshakes, security properties are listed for each handshake
payload.  Transport payloads are listed as arrows without a pattern.  Transport
payloads are only listed if they have different security properties than the
previous handshake payload sent from the same party.  If two transport payloads
are listed, the security properties for the second only apply if the first was
received.

+--------------------------------------------------------------+
|                          Authentication   Confidentiality    |
+--------------------------------------------------------------+
|     Disco_N                     0                2           |
+--------------------------------------------------------------+
|     Disco_K                     1                2           |
+--------------------------------------------------------------+
|     Disco_X                     1                2           |
+--------------------------------------------------------------+
|     Disco_NN                                                 |             
|       -> e                      0                0           |               
|       <- e, ee                  0                1           |               
|       ->                        0                1           |               
+--------------------------------------------------------------+
|     Disco_NK                                                 |                                 
|       <- s                                                   |
|       ...                                                    |                                 
|       -> e, es                  0                2           |               
|       <- e, ee                  2                1           |               
|       ->                        0                5           |               
+--------------------------------------------------------------+
|     Disco_NX                                                 |             
|       -> e                      0                0           |               
|       <- e, ee, s, es           2                1           |               
|       ->                        0                5           |               
+--------------------------------------------------------------+
|     Disco_XN                                                 |                                 
|       -> e                      0                0           |               
|       <- e, ee                  0                1           |               
|       -> s, se                  2                1           |               
|       <-                        0                5           |               
|                                                              |                                 
+--------------------------------------------------------------+
|     Disco_XK                                                 |                                 
|       <- s                                                   |                                 
|       ...                                                    |                                 
|       -> e, es                  0                2           |               
|       <- e, ee                  2                1           |               
|       -> s, se                  2                5           |               
|       <-                        2                5           |               
+--------------------------------------------------------------+
|     Disco_XX                                                 |                                 
|      -> e                       0                0           |               
|      <- e, ee, s, es            2                1           |               
|      -> s, se                   2                5           |               
|      <-                         2                5           |               
+--------------------------------------------------------------+
|     Disco_KN                                                 |                                 
|       -> s                                                   |                                 
|       ...                                                    |                                 
|       -> e                      0                0           |               
|       <- e, ee, se              0                3           |               
|       ->                        2                1           |               
|       <-                        0                5           |               
+--------------------------------------------------------------+
|     Disco_KK                                                 |                                 
|       -> s                                                   |                                 
|       <- s                                                   |                                 
|       ...                                                    |                                 
|       -> e, es, ss              1                2           |               
|       <- e, ee, se              2                4           |               
|       ->                        2                5           |               
|       <-                        2                5           |               
+--------------------------------------------------------------+
|     Disco_KX                                                 |                           
|       -> s                                                   |                           
|       ...                                                    |                                 
|       -> e                      0                0           |               
|       <- e, ee, se, s, es       2                3           |               
|       ->                        2                5           |               
|       <-                        2                5           |               
+--------------------------------------------------------------+
|     Disco_IN                                                 |    
|       -> e, s                   0                0           |         
|       <- e, ee, se              0                3           |         
|       ->                        2                1           |         
|       <-                        0                5           |         
+--------------------------------------------------------------+
|     Disco_IK                                                 |                        
|       <- s                                                   |                        
|       ...                                                    |                        
|       -> e, es, s, ss           1                2           |         
|       <- e, ee, se              2                4           |         
|       ->                        2                5           |         
|       <-                        2                5           |         
+--------------------------------------------------------------+
|     Disco_IX                                                 |                        
|       -> e, s                   0                0           |         
|       <- e, ee, se, s, es       2                3           |         
|       ->                        2                5           |         
|       <-                        2                5           |         
+--------------------------------------------------------------+


7.5. Identity hiding
---------------------

The following table lists the identity hiding properties for all the named
patterns in [Section 7.2](#one-way-patterns) and [Section 7.3](#interactive-patterns).  Each
pattern is assigned properties describing the confidentiality supplied to the
initiator's static public key, and to the responder's static public key.  The
underlying assumptions are that ephemeral private keys are secure, and that
parties abort the handshake if they receive a static public key from the other
party which they don't trust.

This section only considers identity leakage through static public key fields
in handshakes.  Of course, the identities of Disco participants might be
exposed through other means, including payload fields, traffic analysis, or
metadata such as IP addresses.

The properties for the relevant public key are:

  0. Transmitted in clear.

  1. Encrypted with forward secrecy, but can be probed by an
     anonymous initiator.

  2. Encrypted with forward secrecy, but sent to an anonymous responder.

  3. Not transmitted, but a passive attacker can check candidates for
     the responder's private key and determine whether the candidate is correct.

  4. Encrypted to responder's static public key, without forward secrecy.
     If an attacker learns the responder's private key they can decrypt the
     initiator's public key.

  5. Not transmitted, but a passive attacker can check candidates for the pair
     of (responder's private key, initiator's public key) and learn whether the
     candidate pair is correct.

  6. Encrypted but with weak forward secrecy.  An active attacker who
     pretends to be the initiator without the initiator's static private key,
     then later learns the initiator private key, can then decrypt the
     responder's public key.

  7. Not transmitted, but an active attacker who pretends to be the
     initator without the initiator's static private key, then later learns a
     candidate for the initiator private key, can then check whether the
     candidate is correct.

  8. Encrypted with forward secrecy to an authenticated party.

<!-- end of list - necesary to trick Markdown into seeing the following -->

+------------------------------------------+
|                Initiator      Responder  |           
+------------------------------------------+
|     Disco_N        -              3      |
+------------------------------------------+
|     Disco_K        5              5      |
+------------------------------------------+
|     Disco_X        4              3      |
+------------------------------------------+
|     Disco_NN       -              -      |
+------------------------------------------+
|     Disco_NK       -              3      |
+------------------------------------------+
|     Disco_NX       -              1      |
+------------------------------------------+
|     Disco_XN       2              -      |
+------------------------------------------+
|     Disco_XK       8              3      |
+------------------------------------------+
|     Disco_XX       8              1      |
+------------------------------------------+
|     Disco_KN       7              -      |
+------------------------------------------+
|     Disco_KK       5              5      |
+------------------------------------------+
|     Disco_KX       7              6      |
+------------------------------------------+
|     Disco_IN       0              -      |
+------------------------------------------+
|     Disco_IK       4              3      |
+------------------------------------------+
|     Disco_IX       0              6      |
+------------------------------------------+

8. Protocol names
===================

To produce a **Disco protocol name** for `Initialize()` you concatenate the
ASCII names for the handshake pattern, the DH functions, the cipher functions,
and the hash functions, with underscore separators.  The resulting name must be 255
bytes or less.  Examples:

 * `Disco_XX_25519_STROBEv1.0.2`
 * `Disco_N_25519_STROBEv1.0.2`
 * `Disco_IK_448_STROBEv1.0.2`

Disco allows a **modifier** syntax to specify arbitrary extensions or
modifications to default behavior.  For example, a modifier could be applied to
a handshake pattern which transforms it into a different pattern according to some rule.

A modifier is an ASCII string which is added to some component of the Disco
protocol name.  A modifier can be a **pattern modifier**, **DH modifier**,
**cipher modifier**, or **hash modifier**, depending on which component of the
protocol name it is added to.  

The first modifier added onto a base name is simply appended.  Thus, `fallback`
(defined later) is a pattern modifier added to the `Disco_XX` base name to
produce `Disco_XXfallback`.  Additional modifiers are separated with a plus
sign.  Thus, adding the `psk0` pattern modifier (defined in the next section)
would result in the pattern name `Disco_XXfallback+psk0`.

The final protocol name, including all modifiers, must be less than or equal to 255
bytes (e.g. `Disco_XXfallback+psk0_25519_STROBEv1.0.2`).

9. Pre-shared symmetric keys
============

Disco provides a **pre-shared symmetric key** or **PSK** mode to support
protocols where both parties have a 32-byte shared secret key.

9.1. Cryptographic functions
----------------------------------

PSK mode uses the `KEY()` function to mix the PSK into the Strobe state.

9.2. Handshake tokens
-------------------------------

In a PSK handshake, a `"psk"` token is allowed to appear one or more times in a
handshake pattern.  This token can only appear in message patterns (not
pre-message patterns).  This token is processed by calling
`KEY(psk)`, where `psk` is a 32-byte secret value provided by the
application.

In non-PSK handshakes, the `"e"` token in a pre-message pattern or message pattern always
results in a call to `AD(e.public_key)`.  In a PSK handshake, all of these calls
are followed by `AD(e.public_key)`.  In conjunction with the validity rule in the
next section, this ensures that PSK-based encryption uses encryption keys that are randomized using
ephemeral public keys as nonces.

9.3. Validity rule
--------------------

To prevent catastrophic key reuse, handshake patterns using the `"psk"` token must follow an additional validity rule:

 * A party may not send any encrypted data after it processes a `"psk"` token unless it has previously
 sent an ephemeral public key (an `"e"` token), either before or after the `"psk"` token.

This rule guarantees that a `k` derived from a PSK will never be used for
encryption unless it has also been randomized by `AD(e.public_key)`
using a self-chosen ephemeral public key.

9.4. Pattern modifiers
------------

To indicate PSK mode and the placement of the `"psk"` token, pattern modifiers
are used (see [Section 8](#protocol-names)).  The modifier `psk0` places a `"psk"`
token at the beginning of the first handshake message.  The modifiers
`psk1`, `psk2`, etc., place a `"psk"` token at the end of the
first, second, etc., handshake message.  

Any pattern using one of these modifiers must process tokens according to the rules in [Section 9.2](#handshake-tokens]), and must follow the validity rule in [Section 9.3](#validity-rule).

The table below lists some unmodified one-way patterns on the left, and the recommended
PSK pattern on the right:


+--------------------------------+--------------------------------------+
|     Disco_N(rs):               |        Disco_Npsk0(rs):              |
|       <- s                     |          <- s                        |
|       ...                      |          ...                         |
|       -> e, es                 |          -> psk, e, es               |
|                                |                                      |
+--------------------------------+--------------------------------------+
|     Disco_K(s, rs):            |        Disco_Kpsk0(s, rs):           |
|       <- s                     |          <- s                        |
|       ...                      |          ...                         |
|       -> e, es, ss             |          -> psk, e, es, ss           |
|                                |                                      |
+--------------------------------+--------------------------------------+
|     Disco_X(s, rs):            |        Disco_Xpsk1(s, rs):           |
|       <- s                     |          <- s                        |
|       ...                      |          ...                         |
|       -> e, es, s, ss          |          -> e, es, s, ss, psk        |
|                                |                                      |
+--------------------------------+--------------------------------------+

Note that the `psk1` modifier is recommended for `Disco_X`.  This is because
`Disco_X` transmits the initiator's static public key.  Because PSKs are
typically pairwise, the responder likely cannot determine the PSK until it has
decrypted the initiator's static public key.  Thus, `psk1` is likely to be more
useful here than `psk0`.

Following similar logic, we can define the most likely interactive PSK patterns:


+--------------------------------+--------------------------------------+       
|     Disco_NN():                |     Disco_NNpsk0():                  |
|       -> e                     |       -> psk, e                      |
|       <- e, ee                 |       <- e, ee                       |
+--------------------------------+--------------------------------------+
|     Disco_NN():                |     Disco_NNpsk2():                  |
|       -> e                     |       -> e                           |
|       <- e, ee                 |       <- e, ee, psk                  |
+--------------------------------+--------------------------------------+
|     Disco_NK(rs):              |     Disco_NKpsk0(rs):                |
|       <- s                     |       <- s                           |
|       ...                      |       ...                            |
|       -> e, es                 |       -> psk, e, es                  |
|       <- e, ee                 |       <- e, ee                       |
+--------------------------------+--------------------------------------+
|     Disco_NK(rs):              |     Disco_NKpsk2(rs):                |
|       <- s                     |       <- s                           |
|       ...                      |       ...                            |
|       -> e, es                 |       -> e, es                       |
|       <- e, ee                 |       <- e, ee, psk                  |
+--------------------------------+--------------------------------------+
|      Disco_NX(rs):             |      Disco_NXpsk2(rs):               |
|        -> e                    |        -> e                          |
|        <- e, ee, s, es         |        <- e, ee, s, es, psk          |
+--------------------------------+--------------------------------------+
|      Disco_XN(s):              |      Disco_XNpsk3(s):                |
|        -> e                    |        -> e                          |
|        <- e, ee                |        <- e, ee                      |
|        -> s, se                |        -> s, se, psk                 |
+--------------------------------+--------------------------------------+
|      Disco_XK(s, rs):          |      Disco_XKpsk3(s, rs):            |
|        <- s                    |        <- s                          |
|        ...                     |        ...                           |
|        -> e, es                |        -> e, es                      |
|        <- e, ee                |        <- e, ee                      |
|        -> s, se                |        -> s, se, psk                 |
+--------------------------------+--------------------------------------+
|      Disco_XX(s, rs):          |      Disco_XXpsk3(s, rs):            |
|        -> e                    |        -> e                          |
|        <- e, ee, s, es         |        <- e, ee, s, es               |
|        -> s, se                |        -> s, se, psk                 |
+--------------------------------+--------------------------------------+   
|        Disco_KN(s):            |       Disco_KNpsk0(s):               |
|          -> s                  |         -> s                         |
|          ...                   |         ...                          |
|          -> e                  |         -> psk, e                    |
|          <- e, ee, se          |         <- e, ee, se                 |
+--------------------------------+--------------------------------------+   
|        Disco_KN(s):            |       Disco_KNpsk2(s):               |
|          -> s                  |         -> s                         |
|          ...                   |         ...                          |
|          -> e                  |         -> e                         |
|          <- e, ee, se          |         <- e, ee, se, psk            |
+--------------------------------+--------------------------------------+
|        Disco_KK(s, rs):        |       Disco_KKpsk0(s, rs):           |
|          -> s                  |         -> s                         |
|          <- s                  |         <- s                         |
|          ...                   |         ...                          |
|          -> e, es, ss          |         -> psk, e, es, ss            |
|          <- e, ee, se          |         <- e, ee, se                 |
+--------------------------------+--------------------------------------+
|        Disco_KK(s, rs):        |       Disco_KKpsk2(s, rs):           |
|          -> s                  |         -> s                         |
|          <- s                  |         <- s                         |
|          ...                   |         ...                          |
|          -> e, es, ss          |         -> e, es, ss                 |
|          <- e, ee, se          |         <- e, ee, se, psk            |
+--------------------------------+--------------------------------------+
|         Disco_KX(s, rs):       |        Disco_KXpsk2(s, rs):          |
|           -> s                 |          -> s                        |
|           ...                  |          ...                         |
|           -> e                 |          -> e                        |
|           <- e, ee, se, s, es  |          <- e, ee, se, s, es, psk    |
+--------------------------------+--------------------------------------+
|         Disco_IN(s):           |        Disco_INpsk1(s):              |
|           -> e, s              |          -> e, s, psk                |
|           <- e, ee, se         |          <- e, ee, se                |
|                                |                                      |
+--------------------------------+--------------------------------------+
|         Disco_IN(s):           |        Disco_INpsk2(s):              |
|           -> e, s              |          -> e, s                     |
|           <- e, ee, se         |          <- e, ee, se, psk           |
|                                |                                      |
+--------------------------------+--------------------------------------+
|         Disco_IK(s, rs):       |        Disco_IKpsk1(s, rs):          |
|           <- s                 |          <- s                        |
|           ...                  |          ...                         |
|           -> e, es, s, ss      |          -> e, es, s, ss, psk        |
|           <- e, ee, se         |          <- e, ee, se                |
|                                |                                      |
+--------------------------------+--------------------------------------+
|         Disco_IK(s, rs):       |        Disco_IKpsk2(s, rs):          |
|           <- s                 |          <- s                        |
|           ...                  |          ...                         |
|           -> e, es, s, ss      |          -> e, es, s, ss             |
|           <- e, ee, se         |          <- e, ee, se, psk           |
|                                |                                      |
+--------------------------------+--------------------------------------+
|         Disco_IX(s, rs):       |        Disco_IXpsk2(s, rs):          |
|           -> e, s              |          -> e, s                     |
|           <- e, ee, se, s, es  |          <- e, ee, se, s, es, psk    |
|                                |                                      |
+--------------------------------+--------------------------------------+

The above list does not exhaust all possible patterns that can be formed with
these modifiers.  In particular, any of these PSK modifiers can be safely
applied to any previously named pattern, resulting in patterns like
`Disco_IKpsk0`, `Disco_KKpsk1`, or even `Disco_XXpsk0+psk3`, which aren't
listed above.

This still doesn't exhaust all the ways that `"psk"` tokens could be used
outside of these modifiers (e.g. placement of `"psk"` tokens in the middle of a
message pattern).  Defining additional PSK modifiers is outside the scope of
this document.

10. Fallback protocols
=======================

10.1. Fallback patterns
------------------------
So far we've discussed Disco protocols which execute a single handshake
chosen by the initiator.

These include zero-RTT protocols where the initiator encrypts the initial
message based on some stored information about the responder (such as the
responder's static public key).

If the initiator's information is out-of-date the responder won't be able to decrypt the message.  To handle this case, the responder might choose to execute a different Disco handshake (a **fallback handshake**).

To support this case Disco allows **fallback patterns**.  Fallback patterns differ from other handshake patterns in a couple ways:

 * The initiator and responder roles from the pre-fallback handshake are preserved in the fallback handshake.  Thus, the responder sends the first message in a fallback handshake.  In other words, the first handshake message in a fallback pattern is shown with a left-pointing arrow (from the responder) instead of a right-pointing arrow (from the initiator).

 * Any public keys sent in the clear in the initiator's first message are included in the initiator's pre-message in the fallback pattern.  The initiator's pre-message must always include an ephemeral public key.  An ephemeral public key is not otherwise included in the initiator's pre-message (initiators typically transmit an ephemeral public key in their first message).  Thus, the presence of an ephemeral public key in the initiator's pre-message indicates a fallback pattern.

Another caveat for fallback handshakes:  If the initial handshake message has a prologue or payload that the responder makes any decisions based on, then the `h` value after processing that handshake message should be included in the prologue for the fallback handshake.


10.2. Indicating fallback
------------------------

A typical fallback scenario for zero-RTT encryption involves three different Disco handshakes:

 * A **full handshake** is used if the initiator doesn't possess stored information about the responder that would enable zero-RTT encryption, or doesn't wish to use the zero-RTT handshake.

 * A **zero-RTT handshake** allows encryption of data in the initial message.

 * A **fallback handshake** is triggered by the responder if it can't decrypt the initiator's first zero-RTT handshake message.

There must be some way for the responder to distinguish full versus zero-RTT handshakes on receiving the first message.  If the initiator makes a zero-RTT attempt, there must be some way for the initiator to distinguish zero-RTT from fallback handshakes on receiving the second message.

For example, each handshake message could be preceded by a `type` byte (see
[Section 13](#application-responsibilities)).  This byte is not part of the
Disco message proper, but simply signals which handshake is being used:

 * If `type == 0` in the initiator's first message then the initiator is
   performing a full handshake.

 * If `type == 1` in the initiator's first message then the initiator is
   performing a zero-RTT handshake.

 * If `type == 0` in the responder's first response then the
   responder accepted the zero-RTT message.

 * If `type == 1` in the responder's first response then the
   responder failed to decrypt the initiator's zero-RTT message and is
   performing a fallback handshake.

Note that the `type` byte doesn't need to be explicitly authenticated (either as
prologue, or as additional AEAD data), since it's implicitly authenticated if the
message is processed succesfully.

10.3. Disco Pipes
---

This section defines the **Disco Pipe** protocol.  This protocol uses
three handshake patterns - two defined previously, and a new one.  These handshake patterns satisfy the full, zero-RTT, and fallback roles discussed in the previous section, so can be used to provide a full handshake with a simple zero-RTT option:

    Disco_XX(s, rs):  
      -> e
      <- e, ee, s, es
      -> s, se

    Disco_IK(s, rs):                   
      <- s                         
      ...
      -> e, es, s, ss          
      <- e, ee, se

\newpage
&nbsp;

    Disco_XXfallback(e, s, rs):                   
      -> e
      ...
      <- e, ee, s, es
      -> s, se

The `Disco_XX` pattern is used for a **full handshake** if the parties haven't
communicated before, after which the initiator can cache the responder's static
public key.  

The `Disco_IK` pattern is used for a **zero-RTT handshake**.  

The `Disco_XXfallback` pattern is used if the responder fails to decrypt the
first `Disco_IK` message (perhaps due to changing a static key).  In this case
the responder will switch to a **fallback handshake** using `Disco_XXfallback`,
which is identical to `Disco_XX` except the ephemeral public key from the first
`Disco_IK` message is used as the initiator's pre-message.


10.4. Handshake indistinguishability
-----------------------------------

Parties might wish to hide from an eavesdropper which type of handshake they are
performing.  For example, suppose parties are using Disco Pipes, and want to
hide whether they are performing a full handshake, zero-RTT handshake, or
fallback handshake.  

This is fairly easy:

 * The first three messages can have their payloads padded with random bytes to
   a constant size, regardless of which handshake is executed.

 * The responder will attempt to decrypt the first message as a `DiscoIK` message,
   and will fallback to `Disco_XXfallback` if decryption fails.

 * An initiator who sends a `Disco_IK` initial message can use trial decryption
   to differentiate between a response using `Disco_IK` or `Disco_XXfallback`.

 * An initiator attempting a full handshake will send an ephemeral public key, then
 random padding, and will use `Disco_XXfallback` to handle the response.
 Note that `Disco_XX` isn't used, because the server can't
 distinguish a `Disco_XX` message from a failed `Disco_IK` attempt by using trial decryption.

This leaves the Disco ephemeral public keys in the clear.  Ephemeral public
keys are randomly chosen DH public values, but they will typically have enough
structure that an eavesdropper might suspect the parties are using Disco, even
if the eavesdropper can't distinguish the different handshakes.  To make the
ephemerals indistinguishable from random byte sequences, techniques like
Elligator [@elligator] could be used.

11. Advanced features
=====================

11.1. Dummy keys
-----------------

Consider a protocol where an initiator will authenticate herself if the responder
requests it.  This could be viewed as the initiator choosing between patterns
like `Disco_NX` and `Disco_XX` based on some value inside the responder's first
handshake payload.  

Disco doesn't directly support this.  Instead, this could be simulated by
always executing `Disco_XX`.  The initiator can simulate the `Disco_NX` case by
sending a **dummy static public key** if authentication is not requested.  The
value of the dummy public key doesn't matter.

This technique is simple, since it allows use of a single handshake pattern.
It also doesn't reveal which option was chosen from message sizes or
computation time.  It could be extended to allow a `Disco_XX` pattern to
support any permutation of authentications (initiator only, responder only,
both, or none).  

Similarly, **dummy PSKs** (e.g. a PSK of all zeros) would allow a protocol to
optionally support PSKs.

11.2. Channel binding
---------------------
Parties might wish to execute a Disco protocol, then perform authentication at the application layer using signatures, passwords, or something else.

To support this, Disco libraries should expose the final value of h to the application as a **handshake hash** which uniquely identifies the Disco session.

Parties can then sign the handshake hash, or hash it along with their password, to get an authentication token which has a "channel binding" property: the token can't be used by the receiving party with a different sesssion.

11.3. Rekey
-----------
Parties might wish to periodically update their StrobeState using a one-way function, so that a compromise of StrobeState state will not decrypt older messages.  Periodic rekey might also be used to reduce the volume of data encrypted under a single cipher key (this is usually not important with good ciphers, though note the discussion on `AESGCM` data volumes in [Section 14](#security-considerations)).

To enable this, Strobe supports a `RATCHET()` function.

It is up to to the application if and when to perform rekey.  For example:

 * Applications might perform continuous rekey, where they rekey the relevant StrobeState after every transport message sent or received.  This is simple and gives good protection to older ciphertexts, but might be difficult for implementations where changing keys is expensive.

 * Applications might rekey a StrobeState automatically after it has has been used to send or receive some number of messages.

 * Applications might choose to rekey based on arbitrary criteria, in which case they signal this to the other party by sending a message.

Applications must make these decisions on their own; there are no modifiers which specify rekey behavior.


12. DH functions
======================================================

12.1. The `25519` DH functions
----------------------------

 * **`GENERATE_KEYPAIR()`**: Returns a new Curve25519 key pair.

 * **`DH(keypair, public_key)`**: Executes the Curve25519 DH function (aka
   "X25519" in [@rfc7748]).  Invalid public key values will produce an output
   of all zeros.  

     Alternatively, implementations are allowed to detect inputs that
     produce an all-zeros output and signal an error instead.  This behavior is
     discouraged because it adds complexity and implementation variance, and
     does not improve security.  This behavior is allowed because it might
     match the behavior of some software.

 * **`DHLEN`** = 32

12.2. The `448` DH functions
--------------------------

 * **`GENERATE_KEYPAIR()`**: Returns a new Curve448 key pair.

 * **`DH(keypair, public_key)`**: Executes the Curve448 DH function (aka "X448"
   in [@rfc7748]).  Invalid public key values will produce an output of all
   zeros.  

     Alternatively, implementations are allowed to detect inputs that
     produce an all-zeros output and signal an error instead.  This behavior is
     discouraged because it adds complexity and implementation variance, and
     does not improve security.  This behavior is allowed because it might
     match the behavior of some software.

 * **`DHLEN`** = 56


13. Application responsibilities
================================

An application built on Disco must consider several issues:

 * **Choosing crypto functions**:  The `25519` DH functions are recommended for
   typical uses, though the `448` DH functions might offer extra security
   in case a cryptanalytic attack is developed against elliptic curve
   cryptography.  The `448` DH functions should be used with a 512-bit hash
   like Strobe's `PRF(64)`.  The `25519` DH functions may be used with a
   256-bit hash like Strobe's `PRF(32)`, though a 512-bit hash might offer
   extra security in case a cryptanalytic attack is developed
   against the smaller hash functions.

 * **Extensibility**:  Applications are recommended to use an extensible data
   format for the payloads of all messages (e.g. JSON, Protocol Buffers).  This
   ensures that fields can be added in the future which are ignored by older
   implementations.

 * **Padding**:  Applications are recommended to use a data format for the
   payloads of all encrypted messages that allows padding.  This allows
   implementations to avoid leaking information about message sizes.  Using an
   extensible data format, per the previous bullet, will typically suffice.

 * **Session termination**: Applications must consider that a sequence of Disco
   transport messages could be truncated by an attacker.  Applications should
   include explicit length fields or termination signals inside of transport
   payloads to signal the end of an interactive session, or the end of a
   one-way stream of transport messages.

 * **Length fields**:  Applications must handle any framing or additional
   length fields for Disco messages, considering that a Disco message may be up
   to 65535 bytes in length.  If an explicit length field is needed,
   applications are recommended to add a 16-bit big-endian length field prior
   to each message.

 * **Type fields**:  Applications might wish to include a single-byte type
   field prior to each Disco handshake message (and prior to the length field,
   if one is included).  A recommended idiom is for zero to indicate
   no change from the current protocol, and for applications to reject
   messages with an unknown value.  This allows future protocol versions to
   specify fallback handshakes, different versions, or other different types
   of messages during a handshake.

\newpage

14. Security considerations
===========================

This section collects various security considerations:

 * **Session termination**:  Preventing attackers from truncating a stream of
   transport messages is an application responsibility.  See previous section.

 * **Rollback**:  If parties decide on a Disco protocol based on some previous
   negotiation that is not included as prologue, then a rollback attack might
   be possible.  This is a particular risk with fallback handshakes,
   and requires careful attention if a Disco handshake is preceded by
   communication between the parties.

 * **Misusing public keys as secrets**: It might be tempting to use a pattern
   with a pre-message public key and assume that a successful handshake implies
   the other party's knowledge of the public key.  Unfortunately, this is not
   the case, since setting public keys to invalid values might cause
   predictable DH output.  For example, a `Disco_NK_25519` initiator might send
   an invalid ephemeral public key to cause a known DH output of all zeros,
   despite not knowing the responder's static public key. If the parties want
   to authenticate with a shared secret, it should be used as a PSK [@book2].

 * **Channel binding**:  Depending on the DH functions, it might be possible
   for a malicious party to engage in multiple sessions that derive the same
   shared secret key by setting public keys to invalid values that cause
   predictable DH output (as in the previous bullet).  It might also be
   possible to set public keys to equivalent values that cause the same DH
   output for different inputs.  This is why a higher-level protocol should use
   the handshake hash (`h`) for a unique channel binding, instead of `ck`, as
   explained in [Section 11.2](#channel-binding).

 * **Incrementing nonces**:  Reusing a nonce value for `n` with the same key
   `k` for encryption would be catastrophic.  Implementations must carefully
   follow the rules for nonces.  Nonces are not allowed to wrap back to zero
   due to integer overflow, and the maximum nonce value is reserved.  This
   means parties are not allowed to send more than 2^64^-1 transport messages.

 * **Fresh ephemerals**:  Every party in a Disco protocol must send a fresh
   ephemeral public key prior to sending any encrypted data.  Ephemeral keys
   must never be reused.  Violating these rules is likely to cause catastrophic
   key reuse. This is one rationale behind the patterns in [Section
   7](#handshake-patterns), and the validity rules in [Section
   7.1](#pattern-validity).  It's also the reason why one-way handshakes only
   allow transport messages from the sender, not the recipient.

 * **Protocol names**:  The protocol name used with `Initialize()` must
   uniquely identify the combination of handshake pattern and crypto functions
   for every key it's used with (whether ephemeral key pair, static key pair,
   or PSK).  If the same secret key was reused with the same protocol name but
   a different set of cryptographic operations then bad interactions could
   occur.

 * **Pre-shared symmetric keys**:  Pre-shared symmetric keys must be secret
   values with 256 bits of entropy.

 * **Data volumes**:  The `AESGCM` cipher functions suffer a gradual reduction
   in security as the volume of data encrypted under a single key increases.
   Due to this, parties should not send more than 2^56^ bytes (roughly 72
   petabytes) encrypted by a single key.  If sending such large volumes of data
   is a possibility then different cipher functions should be chosen.

 * **Hash collisions**:  If an attacker can find hash collisions on prologue
   data or the handshake hash, they may be able to perform "transcript
   collision" attacks that trick the parties into having different views of
   handshake data.  It is important to use Disco with
   collision-resistant hash functions, and replace the hash function at any
   sign of weakness.

 * **Implementation fingerprinting**:  If this protocol is used in settings
   with anonymous parties, care should be taken that implementations behave
   identically in all cases.  This may require mandating exact behavior for
   handling of invalid DH public keys.


15. Rationales
=============

This section collects various design rationales.

15.1. Ciphers and encryption
--------------

Cipher keys and PSKs are 256 bits because:

  * 256 bits is a conservative length for cipher keys when considering
    cryptanalytic safety margins, time/memory tradeoffs, multi-key attacks,
    rekeying, and quantum attacks.

  * Pre-shared key length is fixed to simplify testing and implementation, and
    to deter users from mistakenly using low-entropy passwords as pre-shared keys.

The authentication data in a ciphertext (i.e. the authentication tag or synthetic IV) is 128 bits because:

  * Some algorithms (e.g. GCM) lose more security than an ideal MAC when
    truncated.

  * Disco may be used in a wide variety of contexts, including where attackers
    can receive rapid feedback on whether guesses for authentication data are correct.

  * A single fixed length is simpler than supporting variable-length tags.



15.2. Other
------------

Big-endian length fields are recommended because:

  * Length fields are likely to be handled by parsing code where
    big-endian "network byte order" is traditional.

  * Some ciphers use big-endian internally (e.g. GCM, SHA2).

  * While it's true that Curve25519, Curve448, and ChaCha20/Poly1305 use
    little-endian, these will likely be handled by specialized libraries, so
    there's not a strong argument for aligning with them.

Session termination is left to the application because:

  * Providing a termination signal in Disco doesn't help the application much,
    since the application still has to use the signal correctly.

  * For an application with its own termination signal, having a
    second termination signal in Disco is likely to be confusing rather than helpful.


16. IPR
========

The Disco specification (this document) is hereby placed in the public domain.

17. Acknowledgements
=====================

Disco is inspired by:

  * The Disco Protocol Framework from Trevor Perrin [@noise].
  * The NaCl and CurveCP protocols from Dan Bernstein et al [@nacl; @curvecp].
  * The SIGMA and HOMQV protocols from Hugo Krawczyk [@sigma; @homqv].
  * The Ntor protocol from Ian Goldberg et al [@ntor].
  * The analysis of OTR by Mario Di Raimondo et al [@otr].
  * The analysis by Caroline Kudla and Kenny Paterson of "Protocol 4" by Simon Blake-Wilson et al [@kudla2005; @blakewilson1997].
  * Mike Hamburg's proposals for a sponge-based protocol framework, which led to STROBE [@moderncryptostrobe; @strobe].
  * The KDF chains used in the Double Ratchet Algorithm [@doubleratchet].

General feedback on the spec and design came from: Moxie Marlinspike, Jason
Donenfeld, Rhys Weatherley, Mike Hamburg, Tiffany Bennett, Jonathan Rudenberg,
Stephen Touset, Tony Arcieri, Alex Wied, Alexey Ermishkin, and Olaoluwa
Osuntokun.

Thanks to Tom Ritter, Karthikeyan Bhargavan, David Wong, Klaus Hartke, Dan
Burkert, Jake McGinty, and Yin Guanhao for editorial feedback.

Moxie Marlinspike, Hugo Krawczyk, Samuel Neves, Christian Winnerlein, J.P.
Aumasson, and Jason Donenfeld provided helpful input and feedback on the key
derivation design.

The PSK approach was largely motivated and designed by Jason Donenfeld, based
on his experience with PSKs in WireGuard.

The rekey design benefited from discussions with Rhys Weatherley, Alexey
Ermishkin, and Olaoluwa Osuntokun.  

The BLAKE2 team (in particular J.P.  Aumasson, Samuel Neves, and Zooko)
provided helpful discussion on using BLAKE2 with Disco.

Jeremy Clark, Thomas Ristenpart, and Joe Bonneau gave feedback on earlier
versions.

\newpage

18.  References
================
