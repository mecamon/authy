package tokens

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokensServ_IssueRefresh(t *testing.T) {
	raw, hashed, err := to.IssueRefresh()
	assert.NoError(t, err)

	hashedRaw := to.HashRawToken(raw)
	assert.Equal(t, hashed, hashedRaw)
}

func TestTokensServ_HashRawToken(t *testing.T) {
	raw, err := to.generateRefreshToken(32)
	require.NoError(t, err)

	hashedRaw := to.HashRawToken(raw)
	assert.NotEqual(t, raw, hashedRaw)
}

func TestTokensServ_IssueAccessCustom(t *testing.T) {
	var tests = map[string]struct {
		base  BaseClaims
		extra map[string]any
		err   error
	}{
		"no_extra_claims": {
			base: BaseClaims{
				Sub: "12938",
				Iss: "http://test-for-token.com",
				Aud: "http://test-for-token.com",
				Exp: uint64(time.Now().Add(time.Minute * time.Duration(10)).Unix()),
				Iat: uint64(time.Now().Unix()),
				Nbf: uint64(time.Now().Unix()),
			},
		},
		"with_extra_claims": {
			base: BaseClaims{
				Sub: "12938",
				Iss: "http://test-for-token.com",
				Aud: "http://test-for-token.com",
				Exp: uint64(time.Now().Add(time.Minute * time.Duration(10)).Unix()),
				Iat: uint64(time.Now().Unix()),
				Nbf: uint64(time.Now().Unix()),
			},
			extra: map[string]any{
				"role": "admin",
				"type": "access",
			},
		},
		"with_extra_claims_overwritting_base": {
			base: BaseClaims{
				Sub: "12938",
				Iss: "http://test-for-token.com",
				Aud: "http://test-for-token.com",
				Exp: uint64(time.Now().Add(time.Minute * time.Duration(10)).Unix()),
				Iat: uint64(time.Now().Unix()),
				Nbf: uint64(time.Now().Unix()),
			},
			extra: map[string]any{
				"iss": "http://overwritten.com",
				"aud": "http://overwrittentoo.com",
			},
		},
		"token_not_valid_yet": {
			base: BaseClaims{
				Sub: "12938",
				Iss: "http://test-for-token.com",
				Aud: "http://test-for-token.com",
				Exp: uint64(time.Now().Add(time.Minute * time.Duration(10)).Unix()),
				Iat: uint64(time.Now().Unix()),
				Nbf: uint64(time.Now().Add(time.Minute * time.Duration(1)).Unix()),
			},
			err: ErrInvalidToken,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			strToken, err := to.IssueOpaque(tt.base, tt.extra)
			require.NoError(t, err)

			claims, err := to.ValidateOpaque(strToken)
			if err != nil {
				assert.ErrorIs(t, err, tt.err)
				return
			}

			// JWT serializes through JSON, so numeric claims come back as
			// float64 and everything else as string. Pull each out with a
			// typed assertion before comparing.
			id, ok := claims["id"].(string)
			assert.True(t, ok)
			sub, ok := claims["sub"].(string)
			assert.True(t, ok)
			iss, ok := claims["iss"].(string)
			assert.True(t, ok)
			aud, ok := claims["aud"].(string)
			assert.True(t, ok)
			exp, ok := claims["exp"].(float64)
			assert.True(t, ok)
			iat, ok := claims["iat"].(float64)
			assert.True(t, ok)
			nbf, ok := claims["nbf"].(float64)
			assert.True(t, ok)

			assert.NotEmpty(t, id)
			assert.Equal(t, tt.base.Sub, sub)
			assert.Equal(t, tt.base.Nbf, uint64(nbf))
			assert.Equal(t, float64(tt.base.Exp), exp)
			assert.Equal(t, float64(tt.base.Iat), iat)

			if name == "with_extra_claims_overwritting_base" {
				extraIss, ok := tt.extra["iss"].(string)
				assert.True(t, ok)
				extraAud, ok := tt.extra["aud"].(string)
				assert.True(t, ok)

				assert.Equal(t, extraIss, iss)
				assert.Equal(t, extraAud, aud)
			} else {
				assert.Equal(t, tt.base.Iss, iss)
				assert.Equal(t, float64(tt.base.Nbf), nbf)
			}
		})
	}
}
