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

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"hash"
	"testing"
)

func TestECDHFundamentals(t *testing.T) {
	// this will just test the fundamentals of ECDH to ensure that our shared keys can be determined
	// this test will always pass; if it doesn't, something is extremely wrong
	testPrivateKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	ephemeralPrivateKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	firstSharedKey, _ := testPrivateKey.ECDH(ephemeralPrivateKey.PublicKey())
	secondSharedKey, _ := ephemeralPrivateKey.ECDH(testPrivateKey.PublicKey())
	if !bytes.Equal(firstSharedKey, secondSharedKey) {
		t.Error("ECDH keys are not equal.")
	}
}

func TestDecryptECIESPortable(t *testing.T) {
	// setup our 2 variables; base64 encoded ciphertext and private key
	encodedPrivKey := "MHcCAQEEIK5xafOSFcD4SjjXMmyOSA2mIq5G9820Lt44PrbagETLoAoGCCqGSM49AwEHoUQDQgAEJmhu07HsJwBmHSgzn2J9LlhsYYQImZ0ldrrLr/Y/Q48iGUEKVFHgIRRvvJybLKaKkvuD8kO7PmkCzXjHEP1c1Q=="
	encodedCiphertext := "BK0G4DUkfBjhiD1UQZPsSXu4IR3dS3PWDfZ77k0g0qF0y1r9Fu6dhzunlThfah7vd0pW5Ba9wPmNmQvjL/sl8NYJ8CudjeJYJAXIuzzfOWIg5Asd6TnADNmN7MNC/Eku+L8="
	// now decode these into their data bytes
	decodedPrivBytes, err := base64.StdEncoding.DecodeString(encodedPrivKey)
	if err != nil {
		t.Errorf("error whilst decoding private key: %v", err)
	}
	decodedCiphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		t.Errorf("error whilst decoding ciphertext from base64: %v", err)
	}
	// parse the private key into an ecdsa.PrivateKey
	var parsedKey interface{}
	parsedKey, _ = x509.ParseECPrivateKey(decodedPrivBytes)
	if parsedKey == nil {
		t.Errorf("error whilst parsing private key: %v", err)
	}
	var pk, _ = parsedKey.(*ecdsa.PrivateKey).ECDH()

	plaintext, err := DecryptECIESX963AESGCM(sha256.New(), true, pk, decodedCiphertext, nil)
	if err != nil {
		t.Errorf("error whilst decrypting: %v", err)
	}
}

func TestEncryptPortable(t *testing.T) {
	// generate a new private key to be used for this test
	privateKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	// marshal the private key as ASN.1 DER data
	marshalledKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Errorf("error whilst marshalling key: %v", err)
	}
	// encode and log the private key as base64
	base64Key := base64.StdEncoding.EncodeToString(marshalledKey)
	t.Log("Private Key:")
	t.Log(base64Key)
	// encode a message to be encrypted
	message := []byte("Hello!")
	// encrypt by passing message and getting ciphertext
	// this setup is the equivalent of .eciesEncryptionCofactorVariableIVX963SHA256AESGCM in swift
	ciphertext, err := EncryptECIESX963AESGCM(sha256.New(), true, privateKey.PublicKey(), message, nil)
	if err != nil {
		t.Errorf("error whilst encrypting: %v", err)
	}
	t.Log("Ciphertext:")
	t.Log(base64.StdEncoding.EncodeToString(ciphertext))
}

func TestExternalDecryptSuccess(t *testing.T) {
	// setup our testing table with every possible variant of
	// the values of each tests ciphertext have been created using Swift and Apple's Security.framework
	// implementation
	// TODO = Add more tests
	tests := map[string]struct {
		key        string
		ciphertext string
		hash       hash.Hash
		variableIV bool
	}{
		"P256-SHA224-0IV": {
			// created with SecKeyAlgorithm .eciesEncryptionCofactorX963SHA224AESGCM
			// on macOS 14.4.1 (23E224)
			key:        "MHcCAQEEIJyzfcyptwjYkgdcFhfJlztLPmcfyzyCFs7NoQuCbAAhoAoGCCqGSM49AwEHoUQDQgAE7WttwmG8qki5bU2utMaugBWbWD9Jx/UPzgnGxthgHteyqPGofBjBwPZTbxj+lrIGNyHRdbOkSusD7051WG8nmg==",
			ciphertext: "BPIMheQOrz0l9wEjcOHQEQ16D9Go8Sm8bEM3LAgMEHUf/eHy3u0oVlfh2po9ocPCuKG2bQ28wlsQ0N6SNJ3O3auS/QeoUogLVcJ3+R1OOeixEJyqeUkn6zB8LcqoZ+Y2",
			hash:       sha256.New224(),
			variableIV: false,
		},
		"P384-SHA224-0IV": {
			// created with SecKeyAlgorithm .eciesEncryptionCofactorX963SHA224AESGCM
			// and P-384 (secp384r1) key (openssl ecparam -name secp384r1 -genkey -noout)
			// on macOS 14.4.1 (23E224)
			key:        "MIGkAgEBBDAI18KI/52miF1/gGpYOOnvkwjXwGz/tOedlcbWhMTEfiAaAHSVTSzxd9Pyun5cRoCgBwYFK4EEACKhZANiAAR498VhIR9tTgyOUFdzJEQyqOU8mCs4mKPHzTcEUgfpX1J85ZOw+oFARLddhHQ7JvmgZfYQNC6CrzoL3H5ockG54Zkq2RV6kmn5mSonQGjD4lJ3ic0B2Jpb4DQHWDbcstA=",
			ciphertext: "BHwqDkIP8+8hwXDlJ3W/Uw4oqVHhpg3Dbj/lx2ukwjwL3xSFNgGpNRhXUIv0Fs2qGxUXGKMGNIa+8/ebvHNuJqjV0pAR52HZ79dQWpB/esIy8/w514TSLSmp6fIk4Yt7gCy+mBKN/bC9nIwMCjiPSdpuhCt+Jc+KZZjgJ7BLUT4=",
			hash:       sha256.New224(),
			variableIV: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			decodedKeyBytes, err := base64.StdEncoding.DecodeString(test.key)
			if err != nil {
				t.Errorf("error whilst decoding private key: %v", err)
			}
			// parse the private key into an ecdsa.PrivateKey
			var parsedKey interface{}
			parsedKey, _ = x509.ParseECPrivateKey(decodedKeyBytes)
			if parsedKey == nil {
				t.Errorf("error whilst parsing private key: %v", err)
			}
			var ecdhKey, _ = parsedKey.(*ecdsa.PrivateKey).ECDH()
			decodedCiphertext, err := base64.StdEncoding.DecodeString(test.ciphertext)
			if err != nil {
				t.Errorf("error whilst decoding ciphertext from base64: %v", err)
			}
			// decrypt by passing ciphertext and getting plaintext
			plaintext, err := DecryptECIESX963AESGCM(test.hash, test.variableIV, ecdhKey, decodedCiphertext, nil)
			if err != nil {
				t.Errorf("error whilst decrypting: %v", err)
			}
			if !bytes.Equal(plaintext, []byte(name)) {
				t.Errorf("messages don't match: expected %v, got %v", []byte(name), plaintext)
			}
		})
	}

}

// TestHelloName calls greetings.Hello with a name, checking
// for a valid return value.
func TestInternalEncryptDecryptSuccess(t *testing.T) {
	// setup our testing table with every possible variant of
	tests := map[string]struct {
		curve      ecdh.Curve
		hash       hash.Hash
		variableIV bool
	}{
		"P256-SHA224-0IV": {
			curve:      ecdh.P256(),
			hash:       sha256.New224(),
			variableIV: false,
		},
		"P256-SHA224-VIV": {
			curve:      ecdh.P256(),
			hash:       sha256.New224(),
			variableIV: true,
		},
		"P256-SHA256-0IV": {
			curve:      ecdh.P256(),
			hash:       sha256.New(),
			variableIV: false,
		},
		"P256-SHA256-VIV": {
			curve:      ecdh.P256(),
			hash:       sha256.New(),
			variableIV: true,
		},
		"P256-SHA384-0IV": {
			curve:      ecdh.P256(),
			hash:       sha512.New384(),
			variableIV: false,
		},
		"P256-SHA384-VIV": {
			curve:      ecdh.P256(),
			hash:       sha512.New384(),
			variableIV: true,
		},
		"P256-SHA512-0IV": {
			curve:      ecdh.P256(),
			hash:       sha512.New(),
			variableIV: false,
		},
		"P256-SHA512-VIV": {
			curve:      ecdh.P256(),
			hash:       sha512.New(),
			variableIV: true,
		},
		"P384-SHA224-0IV": {
			curve:      ecdh.P384(),
			hash:       sha256.New224(),
			variableIV: false,
		},
		"P384-SHA224-VIV": {
			curve:      ecdh.P384(),
			hash:       sha256.New224(),
			variableIV: true,
		},
		"P384-SHA256-0IV": {
			curve:      ecdh.P384(),
			hash:       sha256.New(),
			variableIV: false,
		},
		"P384-SHA256-VIV": {
			curve:      ecdh.P384(),
			hash:       sha256.New(),
			variableIV: true,
		},
		"P384-SHA384-0IV": {
			curve:      ecdh.P384(),
			hash:       sha512.New384(),
			variableIV: false,
		},
		"P384-SHA384-VIV": {
			curve:      ecdh.P384(),
			hash:       sha512.New384(),
			variableIV: true,
		},
		"P384-SHA512-0IV": {
			curve:      ecdh.P384(),
			hash:       sha512.New(),
			variableIV: false,
		},
		"P384-SHA512-VIV": {
			curve:      ecdh.P384(),
			hash:       sha512.New(),
			variableIV: true,
		},
		"P521-SHA224-0IV": {
			curve:      ecdh.P521(),
			hash:       sha256.New224(),
			variableIV: false,
		},
		"P521-SHA224-VIV": {
			curve:      ecdh.P521(),
			hash:       sha256.New224(),
			variableIV: true,
		},
		"P521-SHA256-0IV": {
			curve:      ecdh.P521(),
			hash:       sha256.New(),
			variableIV: false,
		},
		"P521-SHA256-VIV": {
			curve:      ecdh.P521(),
			hash:       sha256.New(),
			variableIV: true,
		},
		"P521-SHA384-0IV": {
			curve:      ecdh.P521(),
			hash:       sha512.New384(),
			variableIV: false,
		},
		"P521-SHA384-VIV": {
			curve:      ecdh.P521(),
			hash:       sha512.New384(),
			variableIV: true,
		},
		"P521-SHA512-0IV": {
			curve:      ecdh.P521(),
			hash:       sha512.New(),
			variableIV: false,
		},
		"P521-SHA512-VIV": {
			curve:      ecdh.P521(),
			hash:       sha512.New(),
			variableIV: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// generate a test private key to be used for this test
			privateKey, _ := test.curve.GenerateKey(rand.Reader)
			// encode the name of the test as the message
			message := []byte(name)
			// encrypt by passing message and getting ciphertext
			ciphertext, err := EncryptECIESX963AESGCM(test.hash, test.variableIV, privateKey.PublicKey(), message, nil)
			if err != nil {
				t.Errorf("error whilst encrypting: %v", err)
			}
			// decrypt by passing ciphertext and getting plaintext
			plaintext, err := DecryptECIESX963AESGCM(test.hash, test.variableIV, privateKey, ciphertext, nil)
			if err != nil {
				t.Errorf("error whilst decrypting: %v", err)
			}
			if !bytes.Equal(plaintext, message) {
				t.Errorf("messages don't match: expected %v, got %v", message, plaintext)
			}
		})
	}

}
