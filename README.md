# package-cryptography-js

Cryptography package for the [Fōrmulæ](https://formulae.org) programming language.

Fōrmulæ is also a software framework for visualization, edition and manipulation of complex expressions, from many fields. The code for an specific field —i.e. arithmetics— is encapsulated in a single unit called a Fōrmulæ **package**.

This repository contains the source code for the **cryptography package**. It is intended for generation of cryptographic keys, for ecryption and decryption, for hasing and to create signatures and verifying them.

The GitHub organization [formulae-org](https://github.com/formulae-org) encompasses the source code for the rest of packages, as well as the [web application](https://github.com/formulae-org/formulae-js).

<!-- Take a look at this [tutorial](https://formulae.org/?script=tutorials/Arithmetic) to know the capabilities of the Fōrmulæ arithmetic package. -->

### Capabilities ###

#### Key management ####

##### Key generation #####

* Generation of asymmetric keys for encryption/decryption. [RSA-OAEP](https://www.rfc-editor.org/rfc/rfc3447#section-7.1) keys with either SHA-1, SHA-256, SHA-384, or SHA-512 digest function.
* Generation of asymmetric keys for signing/verification. [RSASSA-PKCS1-v1_5](https://www.rfc-editor.org/rfc/rfc3447#section-8.2) keys with either SHA-1, SHA-256, SHA-384, or SHA-512 digest function.

The keys are serialized as Base64 from their [PKCS #8 DER-encoded](https://en.wikipedia.org/wiki/PKCS_8) format for private keys, and [Subject Public Key Info (SPKI) DER-encoded](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1) format for public keys.

#### Hashing ####

Supported algorithms:

* SHA-1
* SHA-256
* SHA-384
* SHA-512

#### Encryption

* Encrypt operation
* Decrypt operation

#### Signing ####

* Generation of a digital signture
* Verification of a digital signature
