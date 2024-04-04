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

package ecies

// Package ecies implements the functions required to encrypt and decrypt data using
// the Elliptic Curve Integrated Encryption Scheme, and in particular; Apple's implementation
// as part of Security.framework on iOS & macOS.
//
// It has been designed to be capable of exchanging encrypted data using key's protected by
// the Secure Enclave on Apple platforms (with NIST P-256 elliptic curve keys):
// https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/protecting_keys_with_the_secure_enclave
// as well as other curves supported by ecdh.Curve (P-384, P-521, X25519)
//
// It includes an implementation of the X.963 KDF Key Derivation Function used by Apple's implementation to derive
// shared AES keys and an optional IV/nonce for GCM
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

// DeriveX963KDF derives a key using the ANSI-X9.63-KDF key derivation function outlined here:
// https://datatracker.ietf.org/doc/html/rfc8418#section-2.1
func DeriveX963KDF(algorithm hash.Hash, length int, key []byte, shared []byte) ([]byte, error) {
	// setup our output and counter variables
	output := []byte{}
	counter := 1
	// check to ensure that the length requested is not above maximum
	maxLength := algorithm.Size() * (int(math.Pow(2, 32)) - 1)
	if length > maxLength {
		return nil, errors.New("requested length is too long")
	}
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

// PerformECDH is a simple wrapper function that simply performs a ECDH exchange with a
// provided private and public key
func PerformECDH(privateKey *ecdh.PrivateKey, publicKey *ecdh.PublicKey) ([]byte, error) {
	sharedKey, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}
	return sharedKey, nil
}

// GetEphemeralPublicKey returns a ecdh.PublicKey, either from the supplied raw bytes or freshly
// generated on the supplied curve.
func GetEphemeralPublicKey(curve ecdh.Curve, key []byte) (*ecdh.PublicKey, error) {
	// if key has been supplied, construct a
	if key != nil {
		// create a new public key
		ephemeralKey, err := curve.NewPublicKey(key)
		if err != nil {
			return nil, err
		}
		return ephemeralKey, nil
	} else {
		// generate an ephemeral private key of the same curve type as our
		ephemeralPrivateKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return ephemeralPrivateKey.PublicKey(), nil
	}
}

func DecryptECIESX963AESGCM(algorithm hash.Hash, variableIV bool, key *ecdh.PrivateKey, ciphertext []byte, additionalData []byte) ([]byte, error) {
	// check to see our key length
	// if greater than 65 bytes, this is greater than P-256 and thus
	// uses AES-256 in Apple's implementation
	// default AES keysize at EC keysizes <= 256 is 16 (AES-128) and is 32 (AES-256) at keysizes > 256
	aesKeyLength := 16
	ivLength := 16
	ecKeyLength := len(key.PublicKey().Bytes())
	if ecKeyLength > 65 {
		aesKeyLength = 32
	}

	// check the length of ciphertext to ensure it is at least the minimum
	if len(ciphertext) < ecKeyLength+1+16 {
		return nil, errors.New("ciphertext is not long enough")
	}

	// get our ephemeral public key from the first [ecKeyLength] bytes of the ciphertext
	ephemeralKey, err := GetEphemeralPublicKey(key.Curve(), ciphertext[:ecKeyLength])
	if err != nil {
		return nil, err
	}

	// perform an ECDH exchange to find our shared key
	sharedKey, err := PerformECDH(key, ephemeralKey)
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

func EncryptECIESX963AESGCM(algorithm hash.Hash, variableIV bool, key *ecdh.PublicKey, plaintext []byte, additionalData []byte) ([]byte, error) {
	ivSize := 16
	aesKeySize := 16
	// check to see our key length (P-256 is 65, P-384 is 97)
	// if greater than 65 bytes, this is greater than P-256 and thus
	// uses AES-256 in Apple's implementation
	// default AES keysize at EC keysizes <= 256 is 16 (AES-128) and is 32 (AES-256) at keysizes > 256
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
	sharedKey, err := ephemeralPrivateKey.ECDH(key)
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
	if err != nil {
		return nil, err
	}
	// return a byte slice with the ephemeral public key prepended to the ciphertext
	return append(ephemeralPrivateKey.PublicKey().Bytes(), ciphertext...), nil
}
