# package-cryptography-js

Cryptography package for the [Fōrmulæ](https://formulae.org) programming language.

Fōrmulæ is also a software framework for visualization, edition and manipulation of complex expressions, from many fields. The code for an specific field —i.e. arithmetics— is encapsulated in a single unit called a Fōrmulæ **package**.

This repository contains the source code for the **cryptography package**. It is intended for generation of cryptographic keys, for ecryption and decryption, for hasing and to create signatures and verifying them.

The GitHub organization [formulae-org](https://github.com/formulae-org) encompasses the source code for the rest of packages, as well as the [web application](https://github.com/formulae-org/formulae-js).

<!-- Take a look at this [tutorial](https://formulae.org/?script=tutorials/Arithmetic) to know the capabilities of the Fōrmulæ arithmetic package. -->

### Capabilities ###

#### Key generation ####

* Generation of asymmetric keys for encryption/decryption with the following algorithms:
    * [RSA-OAEP](https://www.rfc-editor.org/rfc/rfc3447#section-7.1)

* Generation of symmetric key for encryption/decryption with the following algorithms:
    * [AES-CTR](https://w3c.github.io/webcrypto/#bib-nist-sp800-38a)
    * [AES-CBC](https://w3c.github.io/webcrypto/#bib-nist-sp800-38a)
    * [AES-GCM](https://w3c.github.io/webcrypto/#bib-nist-sp800-38d)

* Generation of keys for signing/verification with the following algorithms:
    * [RSASSA-PKCS1-v1_5](https://www.rfc-editor.org/rfc/rfc3447#section-8.2)
    * [RSA-PSS](https://w3c.github.io/webcrypto/#bib-rfc3447)
    * [ECDSA](https://w3c.github.io/webcrypto/#bib-rfc6090)
    * [HMAC](https://w3c.github.io/webcrypto/#bib-fips-198-1)

The keys are serialized as Base64 from their [PKCS #8 DER-encoded](https://en.wikipedia.org/wiki/PKCS_8) format for private keys, and [Subject Public Key Info (SPKI) DER-encoded](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1) format for public keys.

#### Hashing ####

Supported algorithms:
* [SHA-1]()
* [SHA-256]()
* [SHA-384]()
* [SHA-512]()

#### Encryption

* Encrypt operation
* Decrypt operation

#### Digital signatures ####

* Generation of a digital signture
* Verification of a digital signature

#### (Pseudo)-randon number generation

* Pseudo-random number generation, but with enough entropy to be suitable for cryptographic purposes.
* It creates a byte buffer of a given size.
