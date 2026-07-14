package pemkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeys(t *testing.T) {
	_, _, err := GenerateKeys()
	assert.NoError(t, err)
}

func TestIsValidPEMPublicKey(t *testing.T) {
	priv, pub, err := GenerateKeys()

	require.NoError(t, err)
	assert.True(t, IsValidPEMPublicKey(pub))
	assert.False(t, IsValidPEMPublicKey(priv))
}

func TestDecodePrivatePEM(t *testing.T) {
	priv, pub, err := GenerateKeys()
	if err != nil {
		t.Error(err)
	}

	var tests = map[string]struct {
		keyBytes    []byte
		expectedErr error
	}{
		"using_a_public_key": {
			keyBytes:    pub,
			expectedErr: ErrNotPrivateRSAKey,
		},
		"using_a_private_key": {
			keyBytes:    priv,
			expectedErr: nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err = DecodePrivatePEM(tt.keyBytes)

			assert.Equal(t, tt.expectedErr, err)
		})
	}
}

func TestSignWithPrivateKey(t *testing.T) {
	challengeBytes := make([]byte, 32)
	_, err := rand.Read(challengeBytes)
	require.NoError(t, err)

	priv, _, err := GenerateKeys()
	assert.NoError(t, err)

	privRSA, err := DecodePrivatePEM(priv)
	assert.NoError(t, err)

	_, err = SignWithPrivateKey(privRSA, challengeBytes)
	assert.NoError(t, err)
}

func TestDecodePublicPEM(t *testing.T) {
	priv, pub, err := GenerateKeys()
	require.NoError(t, err)

	var tests = map[string]struct {
		keyBytes    []byte
		expectedErr error
	}{
		"not_a_public_key": {
			keyBytes:    priv,
			expectedErr: ErrNotPublicRSAKey,
		},
		"a_valid_public_key": {
			keyBytes:    pub,
			expectedErr: nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err = DecodePublicPEM(tt.keyBytes)

			assert.Equal(t, tt.expectedErr, err)
		})
	}
}

func TestVerifySignature(t *testing.T) {
	challengeBytes := make([]byte, 32)
	_, err := rand.Read(challengeBytes)
	require.NoError(t, err)

	//RIGHT KEYS
	priv, pub, err := GenerateKeys()
	assert.NoError(t, err)

	privRSA, err := DecodePrivatePEM(priv)
	assert.NoError(t, err)

	pubRSA, err := DecodePublicPEM(pub)
	assert.NoError(t, err)

	signature, err := SignWithPrivateKey(privRSA, challengeBytes)
	assert.NoError(t, err)

	//WRONG KEYS
	wPriv, wPub, err := GenerateKeys()
	assert.NoError(t, err)

	wPrivRSA, err := DecodePrivatePEM(wPriv)
	assert.NoError(t, err)

	wPubRSA, err := DecodePublicPEM(wPub)
	assert.NoError(t, err)

	wSignature, err := SignWithPrivateKey(wPrivRSA, challengeBytes)
	assert.NoError(t, err)

	var tests = map[string]struct {
		signature   []byte
		pubRSA      *rsa.PublicKey
		expectedErr error
	}{
		"wrong_public_key_1": {
			signature:   signature,
			pubRSA:      wPubRSA,
			expectedErr: rsa.ErrVerification,
		},
		"wrong_signature_2": {
			signature:   wSignature,
			pubRSA:      pubRSA,
			expectedErr: rsa.ErrVerification,
		},
		"correct_signature_and_pub_1": {
			signature:   signature,
			pubRSA:      pubRSA,
			expectedErr: nil,
		},
		"correct_signature_and_pub_2": {
			signature:   wSignature,
			pubRSA:      wPubRSA,
			expectedErr: nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := VerifySignature(tt.pubRSA, challengeBytes, tt.signature)

			assert.Equal(t, tt.expectedErr, err)
		})
	}
}
