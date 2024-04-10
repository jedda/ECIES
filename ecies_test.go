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
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"hash"
	"testing"
)

// v1.0.1

// TestECDHFundamentals tests the fundamentals of ECDH to ensure that our shared keys can be determined
// by generating new fixed and ephemeral key pairs and then ensuring that they calculate the same shared key.
// This test should always pass; if it doesn't, something is extremely wrong.
func TestECDHFundamentals(t *testing.T) {
	testPrivateKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	ephemeralPrivateKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	firstSharedKey, _ := testPrivateKey.ECDH(ephemeralPrivateKey.PublicKey())
	secondSharedKey, _ := ephemeralPrivateKey.ECDH(testPrivateKey.PublicKey())
	if !bytes.Equal(firstSharedKey, secondSharedKey) {
		t.Error("ECDH keys are not equal.")
	}
}

// TestExternalDecryptSuccess is a table driven test suite that tests a series of externally
// encrypted ciphertexts with known keys. These ciphertexts have been created with SecKeyAlgorithms
// using Swift on macOS using various key sizes. These don't currently provide full coverage of the
// possible variations, but there is appropriate coverage of key sizes and hashing algorithms to test
// multiple rounds of the KDF and decryption from AES-128 or AES-256.
func TestExternalDecryptSuccess(t *testing.T) {
	// set up our testing table
	tests := map[string]struct {
		key        string
		ciphertext string
		hash       hash.Hash
		variableIV bool
	}{
		"P256-SHA224-0IV": {
			// created with SecKeyAlgorithm .eciesEncryptionCofactorX963SHA224AESGCM
			// and P-256 (secp256r1) key (openssl ecparam -name secp256r1 -genkey -noout)
			key:        "MHcCAQEEIJyzfcyptwjYkgdcFhfJlztLPmcfyzyCFs7NoQuCbAAhoAoGCCqGSM49AwEHoUQDQgAE7WttwmG8qki5bU2utMaugBWbWD9Jx/UPzgnGxthgHteyqPGofBjBwPZTbxj+lrIGNyHRdbOkSusD7051WG8nmg==",
			ciphertext: "BPIMheQOrz0l9wEjcOHQEQ16D9Go8Sm8bEM3LAgMEHUf/eHy3u0oVlfh2po9ocPCuKG2bQ28wlsQ0N6SNJ3O3auS/QeoUogLVcJ3+R1OOeixEJyqeUkn6zB8LcqoZ+Y2",
			hash:       sha256.New224(),
			variableIV: false,
		},
		"P256-SHA224-VIV": {
			// created with SecKeyAlgorithm .eciesEncryptionCofactorVariableIVX963SHA224AESGCM
			// and P-256 (secp256r1) key (openssl ecparam -name secp256r1 -genkey -noout)
			key:        "MHcCAQEEICc4dTt4v3ZjEQ7aJppfTHLNJKrQUH1pm6127OQsXfjeoAoGCCqGSM49AwEHoUQDQgAEv8iTB0Jx55bGTD/lTVkD8AUqBgMtHiHnO94/I/CGjUEja/TE3dx3aFCjONumJDsW5RPwCK5yTl85yS14/ZeP0g==",
			ciphertext: "BOFS+T9khqnasOma28IAIkquBbdx0yWd71niMjA6Xh+hYRzLrdFEIvNar8oskIL6MbiszIptf4UgoYPnqf+9b/9sM/kljjogttA9lt9zIUJBnRByTg/NScAa5i/nOe96",
			hash:       sha256.New224(),
			variableIV: true,
		},
		"P256-SHA256-VIV": {
			// created with SecKeyAlgorithm .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
			// and P-256 (secp256r1) key (openssl ecparam -name secp256r1 -genkey -noout)
			key:        "MHcCAQEEIHGhxnpu3kG/nW5ozDZJ+TTFQvL6MynCcQWD6jHV4p0UoAoGCCqGSM49AwEHoUQDQgAEzgFYw3Rqc72IIYHV7JH6M245n/nLnxyre1A7sc5nOt31ZyfJQLXGs4dY0cggne28ueXHID5lKz1JNChY49NHYg==",
			ciphertext: "BI6sBCGyf916GQSV3DHOvmFxOmzbV9pq08wcOdKaepP2/Qtepj9M71dYkzXf6OqIstDyyVIxfnAMfUpxZzoCHDbalYRzzwhqHwg7K6RNl1F29PVdLNtJH498yJSfloW/",
			hash:       sha256.New(),
			variableIV: true,
		},
		"P384-SHA224-0IV": {
			// created with SecKeyAlgorithm .eciesEncryptionCofactorX963SHA224AESGCM
			// and P-384 (secp384r1) key (openssl ecparam -name secp384r1 -genkey -noout)
			key:        "MIGkAgEBBDAI18KI/52miF1/gGpYOOnvkwjXwGz/tOedlcbWhMTEfiAaAHSVTSzxd9Pyun5cRoCgBwYFK4EEACKhZANiAAR498VhIR9tTgyOUFdzJEQyqOU8mCs4mKPHzTcEUgfpX1J85ZOw+oFARLddhHQ7JvmgZfYQNC6CrzoL3H5ockG54Zkq2RV6kmn5mSonQGjD4lJ3ic0B2Jpb4DQHWDbcstA=",
			ciphertext: "BHwqDkIP8+8hwXDlJ3W/Uw4oqVHhpg3Dbj/lx2ukwjwL3xSFNgGpNRhXUIv0Fs2qGxUXGKMGNIa+8/ebvHNuJqjV0pAR52HZ79dQWpB/esIy8/w514TSLSmp6fIk4Yt7gCy+mBKN/bC9nIwMCjiPSdpuhCt+Jc+KZZjgJ7BLUT4=",
			hash:       sha256.New224(),
			variableIV: false,
		},
		"P384-SHA384-VIV": {
			// created with SecKeyAlgorithm .eciesEncryptionCofactorVariableIVX963SHA384AESGCM
			// and P-384 (secp384r1) key (openssl ecparam -name secp384r1 -genkey -noout)
			key:        "MIGkAgEBBDC5Lt6wBRiiEC2O71i3lv8Jtgg+YP4Y3gCj7B7nOtdQO/5PQPRjpFPJ3ft0yjbzHEagBwYFK4EEACKhZANiAAToVnztZKN1KVhot+MoN3CiPDZ0PoCDXrdP1uHQ61nz4XVrNdxgxyNUJC6cd0gsbujme66wxrq28zqWYBKvrFtIlS4W+NkuyCi5nABkHno7alAWv/fD7aQ8A3ZmWZohsaU=",
			ciphertext: "BM45TREbxELfwpTVBmltz+sB3vhkM85m/yiAsE8JSNmXVOeeUGzmxP5Z2jegApPxtOS8ilfhTN/m2XkOoJWGw3MKuekq5V5PcdvAi5xKcoOEynkS7uAKS3nhBH/+g+9/iNoTcRSrEpbgm8dOCGe+VRQ7hK8vI0ZRw74kernlNDw=",
			hash:       sha512.New384(),
			variableIV: true,
		},
		"P384-SHA384-0IV": {
			// created with SecKeyAlgorithm .eciesEncryptionCofactorX963SHA384AESGCM
			// and P-384 (secp384r1) key (openssl ecparam -name secp384r1 -genkey -noout)
			key:        "MIGkAgEBBDCveSReIMZa6hbWVgmESfu/jMpEqIldBHcx4nQ46zxJ+hvm4lnesKrn0P0BkFYZ0jSgBwYFK4EEACKhZANiAAT0ctzSPeNUinYOJdYtCafXAsTKHLGY4WPPRM8pYL5x1UrvnPN0G1yiF4QsTX2Pgyvh2qositdwRGxv3ruo1yR8TcztRXugZF4a\n5xmcZuQW8hcEmPuk+xS5XXUMzryiEQc=",
			ciphertext: "BERkPl0YZUa9r7JV4W6n/rxsGBpzwdCpIgRaOKxRYuLHx3v5hGnTM1oGOEZzJQnpfvtperUyFfnPB5GP5ioxK4YkrqfjIlF0ip18v30o7TWReJ+MrKYWcC7/TGe/SxPagi/zX9uz4N0Jzp3GFarI5LUQ9mJNIna/3ajuBC9Du94=",
			hash:       sha512.New384(),
			variableIV: false,
		},
		"P521-SHA512-0IV": {
			// created with SecKeyAlgorithm .eciesEncryptionCofactorX963SHA512AESGCM
			// and P-521 (secp521r1) key (openssl ecparam -name secp521r1 -genkey -noout)
			key:        "MIHcAgEBBEIAqKpwdZ9JdC3JdVpM7gj1Bgkep3LNTkYWqEYqwNe5w7oyzDh1yU0LVZzefyZNdaagU6DGNdZ+5u9cHqnh9GrQ5gWgBwYFK4EEACOhgYkDgYYABAD+MDxfbvbe9ZRZcZgWyDBbpf3JxHii0iScjxNqNWClJWlehHfX8niGE6VNktRQ3lMIwDSvUy3Esiex3gu8RHZnwAGzPjwLm1/w2YbOfp2TCNTL8m6eYUfLU0SNW7B61koL+Sk50yTHoseP7+lmM2t8x6uKsyLdo+XCIevpW8IEh0s5wg==",
			ciphertext: "BABqJoMa89aD0rRkZ+WrmWTeqUfcr3uvLmyk7KlbWPm45m0ptDeqsaxFtqeM0VR6IoBMQcvcCcW+hzlLPr7i15LJlADzKYe7al7Vp10fJBnnhM2K7Z12o/VtOynEEt+ed5IkP9BiopN/3swl79caHQqXxX+SWQijwosMh0rGFJZPjsPFcPpe8Aj9CiJ3y0hRH1D4fp+qtpx9LOBLyuXvRwdFi0Y=",
			hash:       sha512.New(),
			variableIV: false,
		},
		"P521-SHA512-VIV": {
			// created with SecKeyAlgorithm .eciesEncryptionCofactorVariableIVX963SHA512AESGCM
			// and P-521 (secp521r1) key (openssl ecparam -name secp521r1 -genkey -noout)
			key:        "MIHcAgEBBEIAg0dkiDMo6frSBz50hC2luT3T0oMv/nPnu4nUR+x9PWuGic4cBHkrlrUOwyTBfGmug8fYxNy2ytJhBEyCGookSK+gBwYFK4EEACOhgYkDgYYABACAYs51q+pIrE2k92p2ltjs0iBHTe8Kj+w1+x5hfmXS1tX0aR+kabb5qe6Q83Bsvq/dmj3R\n59XWmIaTz6tJprSr2gDqS2i9wpWspmDND2dYvhKECXj099CQt19V94qYyUjbXMEDkpvq5ZWQ2DBOnR3XnuwWOYj+Pskg0lseKkok4CtJ4A==",
			ciphertext: "BABIki+hjR7WmHUZz03yTelbH+eEwn0Dtpv8Fxwh7cyaue2ZceAytjlbQD2YA3FHC2Z0NMlk/B0C2Es8dZmPE9keEgBsUW0PjT4CyefgFIc2YEm5yDpcbJEKhj6FlGnOir1nJz8ZMTMdiY6vIrRCBLo6+Ek7iSfQIOGrdER3ESnE/gOdWsd4O3VmDQrwLboTIjKfngmBGlC5sdYUzSbQlsX2UUs=",
			hash:       sha512.New(),
			variableIV: true,
		},
	}
	// run our tests
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			decodedKeyBytes, err := base64.StdEncoding.DecodeString(test.key)
			if err != nil {
				t.Errorf("error whilst decoding private key: %v", err)
				return
			}
			// parse the private key into an ecdsa.PrivateKey
			parsedKey, err := x509.ParseECPrivateKey(decodedKeyBytes)
			if err != nil {
				t.Errorf("error whilst parsing private key: %v", err)
				return
			}
			ecdhKey, err := parsedKey.ECDH()
			if err != nil {
				t.Errorf("error whilst converting key to ecdh: %v", err)
				return
			}
			decodedCiphertext, err := base64.StdEncoding.DecodeString(test.ciphertext)
			if err != nil {
				t.Errorf("error whilst decoding ciphertext from base64: %v", err)
			}
			// decrypt by passing ciphertext and getting plaintext
			plaintext, err := DecryptECIESX963AESGCM(test.hash, test.variableIV, ecdhKey, decodedCiphertext, nil)
			if err != nil {
				t.Errorf("error whilst decrypting: %v", err)
				return
			}
			if !bytes.Equal(plaintext, []byte(name)) {
				t.Errorf("messages don't match: expected %v, got %v", []byte(name), plaintext)
			}
		})
	}
}

// TestInternalEncryptDecryptSuccess is a table driven test suite that encrypts and decrypts variants of ECIES
// It should provide full coverage for the possible key sizes and algorithms provided by Apple's ECIES implementation
// as part of Security.framework (except for SHA1 variants)
func TestInternalEncryptDecryptSuccess(t *testing.T) {
	// set up our testing table
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
		"X25519-SHA512-VIV": {
			curve:      ecdh.X25519(),
			hash:       sha512.New(),
			variableIV: true,
		},
	}
	// run our tests
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
