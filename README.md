# package-cryptography-js

Cryptography package for the [Fōrmulæ](https://formulae.org) programming language.

Fōrmulæ is also a software framework for visualization, edition and manipulation of complex expressions, from many fields. The code for an specific field —i.e. arithmetics— is encapsulated in a single unit called a Fōrmulæ **package**.

This repository contains the source code for the **cryptography package**. It is intended for generation of cryptographic keys, for ecryption and decryption, for hasing and to create signatures and verifying them.

The GitHub organization [formulae-org](https://github.com/formulae-org) encompasses the source code for the rest of packages, as well as the [web application](https://github.com/formulae-org/formulae-js).

<!-- Take a look at this [tutorial](https://formulae.org/?script=tutorials/Arithmetic) to know the capabilities of the Fōrmulæ arithmetic package. -->

### Description ###

The Fōrmulæ cryptography package is basically a wrapper of the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

> [!IMPORTANT]  
> [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) is a powerful, low-level cryptography suite which uses real cryptographic algorithms and parameters. This Fōrmulæ package is intended to provide a higher-level interface to users and programmers. However, as with [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API), it is highly recommended that you have a medium to high knowledge of the cryptographic concepts and mathematical background to be used effectively in production.
> 
> On the other hand, it is very suitable for educational purposes, but again, a basic to medium knowledge of cryptographic concepts is assumed.

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

#### Key serialization ####

<table>
<tr><th>Algorithm<th>Key type<th>Usage<th>Key serialization
<tr><td>RSA-OAEP<td>Private<td>Decrypt<td rowspan="4">Base64 format from their <a href="https://en.wikipedia.org/wiki/PKCS_8">PKCS #8 DER-encoded</a> format</td>
<tr><td>RSASSA-PKCS1-v1_5<td>Private<td>Sign
<tr><td>RSA-PSS<td>Private<td>Sign
<tr><td>ECDSA<td>Private<td>Sign
<tr><td>RSA-OAEP<td>Public<td>Encrypt<td rowspan="4">Base64 format from their <a href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.1)">Subject Public Key Info (SPKI) DER-encoded</a> format</td>
<tr><td>RSASSA-PKCS1-v1_5<td>Public<td>Verify
<tr><td>RSA-PSS<td>Public<td>Verify
<tr><td>ECDSA<td>Public<td>Verify
<tr><td>AES-CTR<td>Secret<td>Encrypt/decrypt<td rowspan="5">Base64 format from their raw bytes</td>
<tr><td>AES-CBC<td>Secret<td>Encrypt/decrypt
<tr><td>AES-GCM<td>Secret<td>Encrypt/decrypt
<tr><td>HMAC<td>Private<td>Sign
<tr><td>HMAC<td>Public<td>Verify
</table>

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

#### Randon number generation

* Pseudo-random number generation, but with enough entropy to be suitable for cryptographic purposes.
* It creates a byte buffer of a given size.
