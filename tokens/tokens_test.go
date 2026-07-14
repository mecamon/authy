package tokens

import (
	"testing"

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
