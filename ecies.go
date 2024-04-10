// Package ecies implements the functions required to encrypt and decrypt data using the Elliptic Curve Integrated Encryption Scheme with X9.63 Key Derivation, and specifically; Apple's implementation as part of the Security framework on iOS & macOS.
package ecies

// MIT License
//
// Copyright (c) 2024 Jedda Wignall
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash"
	"math"
)

// v1.0.1

// EncryptECIESX963AESGCM takes a plaintext []byte slice along with the following parameters and encrypts it to ciphertext.
// The returned ciphertext data can be decrypted by [SecKeyCreateDecryptedData()] on Apple platforms.
//
//   - algorithm is the underlying hashing algorithm used by the KDF
//   - variableIV determines if additional bits from the KDF are used as a nonce/IV for AES-GCM
//   - key is the [ecdh.PublicKey] used to perform ECDH and determine the shared key
//   - additionalData is optional data used by AES-GCM to authenticate (it is not used in Apple's implementation)
//
// If successful, it returns ciphertext data as a []byte slice, or an error if it fails.
//
// [SecKeyCreateDecryptedData()]: https://developer.apple.com/documentation/security/1644043-seckeycreatedecrypteddata
func EncryptECIESX963AESGCM(algorithm hash.Hash, variableIV bool, key *ecdh.PublicKey, plaintext []byte, additionalData []byte) ([]byte, error) {
	ivSize := 16
	aesKeySize := 16
	// check our EC key size
	// if greater than 65 bytes, this is greater than P-256 and thus uses AES-256 in Apple's implementation
	// default AES keysize at EC keysizes <= 256 bits is 16 bits (AES-128) and is 32 bits (AES-256) at keysizes > 256 bits
	ecKeyLength := len(key.Bytes())
	if ecKeyLength > 65 {
		aesKeySize = 32
	}
	// generate an ephemeral private key of the same curve type as our public key
	ephemeralPrivateKey, err := key.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// perform an ECDH exchange to find our shared key
	sharedKey, err := performECDH(ephemeralPrivateKey, key)
	if err != nil {
		return nil, err
	}
	// now we use X9.63 KDF to derive the final key we will use for AES and potential IV
	derivedKey, err := DeriveX963KDF(algorithm, aesKeySize+ivSize, sharedKey, ephemeralPrivateKey.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}

	// initialise an empty IV by default
	iv := make([]byte, ivSize)
	if variableIV {
		// in variable IV algorithms, Apple currently uses the 16 bits of the
		// derived key immediately following the AES key as an IV to GCM
		iv = derivedKey[aesKeySize:(aesKeySize + ivSize)]
	}
	// setup our AES block cipher with the correct length from the derived key
	// this is 16 bits for AES-128 and 32 bits for AES-256
	block, err := aes.NewCipher(derivedKey[:aesKeySize])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, ivSize)
	if err != nil {
		return nil, err
	}
	// finally, determine our plaintext from our ciphertext by providing the encrypted message with it's 16 bit tag
	ciphertext := gcm.Seal(nil, iv, plaintext, additionalData)
	// return a byte slice with the ephemeral public key prepended to the ciphertext
	return append(ephemeralPrivateKey.PublicKey().Bytes(), ciphertext...), nil
}

// DecryptECIESX963AESGCM takes a ciphertext []byte slice along with the following parameters and decrypts it to plaintext.
// The ciphertext data can be created by [SecKeyCreateEncryptedData()] on Apple platforms.
//
//   - algorithm is the underlying hashing algorithm used by the KDF
//   - variableIV determines if additional bits from the KDF are used as a nonce/IV for AES-GCM
//   - key is the [ecdh.PublicKey] used to perform ECDH and determine the shared key
//   - additionalData is optional data used by AES-GCM to authenticate (it is not used in Apple's implementation)
//
// If successful, it returns plaintext data as a []byte slice, or an error if it fails.
//
// [SecKeyCreateEncryptedData()]: https://developer.apple.com/documentation/security/1643957-seckeycreateencrypteddata
func DecryptECIESX963AESGCM(algorithm hash.Hash, variableIV bool, key *ecdh.PrivateKey, ciphertext []byte, additionalData []byte) ([]byte, error) {
	// check our EC key size
	// if greater than 65 bytes, this is greater than P-256 and thus uses AES-256 in Apple's implementation
	// default AES keysize at EC keysizes <= 256 bits is 16 bits (AES-128) and is 32 bits (AES-256) at keysizes > 256 bits
	aesKeyLength := 16
	ivLength := 16
	ecKeyLength := len(key.PublicKey().Bytes())
	if ecKeyLength > 65 {
		aesKeyLength = 32
	}

	// check the length of ciphertext to ensure it is at least the minimum (keysize+1+tag)
	if len(ciphertext) < ecKeyLength+1+16 {
		return nil, errors.New("ciphertext is not long enough to be valid")
	}

	// get our ephemeral public key from the first [ecKeyLength] bytes of the ciphertext
	ephemeralKey, err := getEphemeralPublicKey(key.Curve(), ciphertext[:ecKeyLength])
	if err != nil {
		return nil, err
	}

	// perform an ECDH exchange to find our shared key
	sharedKey, err := performECDH(key, ephemeralKey)
	if err != nil {
		return nil, err
	}

	// now we use X9.63 KDF to derive the final key we will use for AES and potential IV
	derivedKey, err := DeriveX963KDF(algorithm, aesKeyLength+ivLength, sharedKey, ephemeralKey.Bytes())
	if err != nil {
		return nil, err
	}

	// initialise an empty IV by default
	iv := make([]byte, ivLength)
	if variableIV {
		// in variable IV algorithms, Apple uses the 16 bits of the derived key immediately following the
		// AES key as an IV to GCM
		iv = derivedKey[aesKeyLength:(aesKeyLength + ivLength)]
	}
	// setup our AES block cipher with the correct length from the derived key
	// this is 16 bits for AES-128 and 32 bits for AES-256
	block, err := aes.NewCipher(derivedKey[:aesKeyLength])
	if err != nil {
		return nil, err
	}
	// setup our gcm with our aes block and IV size
	gcm, err := cipher.NewGCMWithNonceSize(block, ivLength)
	if err != nil {
		return nil, err
	}
	// finally, determine our plaintext from our ciphertext by providing the encrypted message
	// with it's appended 16 byte tag
	plaintext, err := gcm.Open(nil, iv, ciphertext[ecKeyLength:], additionalData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// DeriveX963KDF derives a key using the ANSI-X9.63-KDF
// key derivation function outlined in [RFC 8418 2.1].
// It returns a byte slice of chosen length, performing
// multiple rounds of the chosen hashing algorithm if required.
//
// [RFC 8418 2.1]: https://datatracker.ietf.org/doc/html/rfc8418#section-2.1
func DeriveX963KDF(algorithm hash.Hash, length int, key []byte, shared []byte) ([]byte, error) {
	// setup our output and counter variables
	var output []byte
	counter := 1
	// check to ensure that the length requested is not above maximum
	maxLength := algorithm.Size() * (int(math.Pow(2, 32)) - 1)
	if length > maxLength {
		return nil, errors.New("requested length is too long")
	}
	// perform enough rounds to fill out the requested length
	for length > len(output) {
		// add our key to the hash
		algorithm.Write(key)
		// add our counter to the hash; this will increment with each round of the KDF
		algorithm.Write(binary.BigEndian.AppendUint32(nil, uint32(counter)))
		// if supplied, add our shared info to the hash
		if shared != nil {
			algorithm.Write(shared)
		}
		// add this round of the KDF to the output
		output = algorithm.Sum(output)
		// reset our hash and increment our counter for the next possible round
		algorithm.Reset()
		counter++
	}
	// return our output limited to the requested length
	return output[:length], nil
}

// performECDH is a simple wrapper function that performs
// a ECDH exchange with a provided private and public keys
// and returns the shared key as a data slice.
func performECDH(privateKey *ecdh.PrivateKey, publicKey *ecdh.PublicKey) ([]byte, error) {
	sharedKey, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}
	return sharedKey, nil
}

// getEphemeralPublicKey creates and returns a [ecdh.PublicKey],
// either from supplied raw bytes or freshly generated on the supplied curve.
func getEphemeralPublicKey(curve ecdh.Curve, key []byte) (*ecdh.PublicKey, error) {
	// if key has been supplied, construct it and return
	if key != nil {
		// create a new public key
		ephemeralKey, err := curve.NewPublicKey(key)
		if err != nil {
			return nil, err
		}
		return ephemeralKey, nil
	} else {
		// generate an ephemeral private key of the same curve type
		ephemeralPrivateKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return ephemeralPrivateKey.PublicKey(), nil
	}
}
