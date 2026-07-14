package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrWrongTokenType = errors.New("wrong token subject")
	ErrParseClaims    = errors.New("it could not parse claims")
	ErrInvalidToken   = errors.New("invalid token")
)

func New(privKeyRSA *rsa.PrivateKey) *TokenServ {
	return &TokenServ{privKeyRSA: privKeyRSA}
}

type TokenServ struct {
	privKeyRSA *rsa.PrivateKey
}

type BaseClaims struct {
	Sub string
	Iss string
	Aud string
	Exp uint64 //seconds
	Iat uint64
	Nbf uint64
}

// IssueRefresh returns the raw token for the client, the hashStr to be stored, a refresh payload and a possible error.
// The hashStr value is hash using deterministic cryptographic hash like SHA-256, otherwise with a non-deterministic,
// it would be impossible to get the same hash for the same input. This works perfectly for encrypting refresh tokens, since
// it will be recieved back to request new access tokens and refresh tokens and we will have to hash it
// and generate exactly the same hash to be able to look for it in our storerage/db/etc.
func (t *TokenServ) IssueRefresh() (
	raw string,
	hashStr string,
	err error,
) {
	raw, err = t.generateRefreshToken(32) //32 is perfect. Anything less than this is fragile/weak
	if err != nil {
		return "", "", err
	}

	hashStr = t.HashRawToken(raw)

	return raw, hashStr, nil
}

// generateRefreshToken returns a random sequence of bytes to be used as a refresh token
func (t *TokenServ) generateRefreshToken(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes) // crypto/rand, secure RNG
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes), nil
}

// HashRawToken returns a hash of a raw token. It is intended to hash tokens before
// storing them or to hash them to look for values stored.
func (t *TokenServ) HashRawToken(raw string) string {
	// Hash the raw token
	hash := sha256.Sum256([]byte(raw))

	return hex.EncodeToString(hash[:])
}

// IssueAccessCustom generates an Access Token (JWT) with a fixed base claims and optional extra claims.
// Bear in mind that if any key has the same name as any of the properties in the base claims, this will be overwritten.
func (t *TokenServ) IssueAccessCustom(base BaseClaims, extra ...map[string]any) (string, error) {
	claims := t.generateClaims(base, extra...)

	return t.issueSignedJWT(claims)
}

// issueSignedJWT returns a signed jwt token in string format, signed by a RSA private key
func (t *TokenServ) issueSignedJWT(claims jwt.MapClaims) (string, error) {
	accessJWT := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Signature changed from Secret []byte to *rsa.PrivateKey to facilitate the validation with public key
	// as a generic authentication service.
	return accessJWT.SignedString(t.privKeyRSA)
}

// ValidateAccessCustom checks a signed JWT string to see if complys with the token type, the secret key, if it is already expired
// or if it has been altered. This is meant to be used to validate any token issued by IssueAccess or IssueAccessCustom.
func (t *TokenServ) ValidateAccessCustom(signed string, tokenType string) (jwt.MapClaims, error) {
	N := t.privKeyRSA.PublicKey.N
	E := t.privKeyRSA.PublicKey.E

	pubKey := &rsa.PublicKey{N: N, E: E}

	// Verify signature
	parsed, err := jwt.Parse(signed, func(t *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	if claims, ok := parsed.Claims.(jwt.MapClaims); ok && parsed.Valid {
		if claims["type"] != tokenType {
			return nil, ErrWrongTokenType
		}

		return claims, nil
	} else {
		return nil, ErrParseClaims
	}
}

// generateClaims returns opaque claims to be used as access tokens.
// Be aware that extra claims with the same key as the ones in BaseClaims will overwrite the value in BaseClaims.
func (t *TokenServ) generateClaims(base BaseClaims, extra ...map[string]any) jwt.MapClaims {
	claimsID := uuid.New().String()

	claims := jwt.MapClaims{
		"id":  claimsID,
		"sub": base.Sub,
		"iss": base.Iss,
		"aud": base.Aud,
		"exp": base.Exp,
		"iat": base.Iat,
		"nbf": base.Nbf,
	}

	// merging base claims with extra claims
	for _, e := range extra {
		for k, v := range e {
			claims[k] = v
		}
	}

	return claims
}
