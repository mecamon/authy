package pemkeys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var (
	ErrNotPrivateRSAKey = errors.New("failed to decode PEM block containing private key")
	ErrNotPublicRSAKey  = errors.New("not a valid RSA public key")
)

// IsValidPEMPublicKey is to validate that the given pemData data is valid
// public key in PEM format.
func IsValidPEMPublicKey(pemData []byte) bool {
	// Decode the PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return false
	}

	// Check PEM block type
	if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" && block.Type != "EC PUBLIC KEY" {
		return false
	}

	// Try parsing the public key to verify the content is valid
	_, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}

	return true
}

// GenerateKeys returns a private key and a public key in PEM format.
// The third return value is an possible error.
func GenerateKeys() (privatePEM, publicPEM []byte, err error) {
	// 1. Generate a new RSA private key
	privateKey, privErr := rsa.GenerateKey(rand.Reader, 2048)
	if privErr != nil {
		err = privErr
		return
	}

	// 2. Encode the private key into PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// 3. Extract the public key and encode into PEM
	publicKeyBytes, pubErr := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if pubErr != nil {
		err = pubErr
		return
	}
	publicPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return
}

func SignWithPrivateKey(privateKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	// Hash the message
	hashed := sha256.Sum256(message)

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func VerifySignature(pubKey *rsa.PublicKey, message, sig []byte) error {
	// Hash the message (same as during signing)
	hashed := sha256.Sum256(message)

	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], sig)
}

func DecodePrivatePEM(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, ErrNotPrivateRSAKey
	}

	// Parse the DER bytes into *rsa.PrivateKey
	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return parsedKey, nil
}

func DecodePublicPEM(keyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, ErrNotPublicRSAKey
	}

	switch block.Type {
	case "PUBLIC KEY":
		// This is usually an X.509 SubjectPublicKeyInfo (PKIX) structure
		pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		pubKey, ok := pubInterface.(*rsa.PublicKey)
		if !ok {
			return nil, ErrNotPublicRSAKey
		}
		return pubKey, nil

	case "RSA PUBLIC KEY":
		// This is the older PKCS#1 format
		pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return pubKey, nil

	default:
		return nil, ErrNotPublicRSAKey
	}
}
