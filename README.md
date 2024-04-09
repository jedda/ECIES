# ECIES

Package `ecies` implements the functions required to encrypt and decrypt data using the Elliptic Curve Integrated Encryption Scheme with X9.63 Key Derivation, and specifically; Apple's [implementation as part of Security.framework](https://developer.apple.com/documentation/security/1643957-seckeycreateencrypteddata) on iOS & macOS.

It has been designed to be capable of exchanging encrypted data using key's [protected by the Secure Enclave on Apple platforms](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/protecting_keys_with_the_secure_enclave) (with NIST P-256 elliptic curve keys) as well as other curves supported by ecdh.Curve (P-384, P-521, X25519).

This package includes an implementation of the X.963 KDF Key Derivation Function used by Apple's framework to derive shared AES keys and an optional IV/nonce for GCM.

### EC & AES Key Sizes

This package follows the behaviour of Apple's when it comes to AES key size selection. For 256 bit EC keys, 16 bits of the derived key are used for AES, leading to AES-128 being used for the symmetric encryption. Where EC key sizes > 256 bits are used (384, 521), 32 bits of the derived key are used for AES, resulting in AES-256 symmetric encryption.

### Ciphertext Format

Ciphertext is outputted and expected in the following format (to match that outputted and expected by [`SecKeyCreateEncryptedData`](https://developer.apple.com/documentation/security/1643957-seckeycreateencrypteddata) and [`SecKeyCreateDecryptedData`](https://developer.apple.com/documentation/security/1644043-seckeycreatedecrypteddata)):

``[ephemeral public key (raw bytes)] + [message ciphertext] + [AES-GCM authentication tag]``

### Companion Swift Playground

A companion Swift Playground project exists here with instructions and examples of how to encrypt and decrypt data compatible with this package.

### Unit Tests

A series of unit tests are included to test the fundamentals as well as some concrete encrypt and decrypt operations. The test `TestExternalDecryptSuccess` includes test data encrypted by Security.framework on macOS with detailed examples as to configuration and algorithm choice.
