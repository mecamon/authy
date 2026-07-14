package encrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateHashFromRaw(t *testing.T) {
	v := "some-test-value-to-hash"
	hashedValue, err := GenerateHashFromRaw(v)

	assert.NoError(t, err)
	assert.NotEqual(t, v, hashedValue)
}

func TestComparePasswordAndHash(t *testing.T) {
	input := "el-quijote-es-un-buen-libro"
	hash, err := GenerateHashFromRaw(input)
	require.NoError(t, err)

	input2 := "el-principito-$-asdasd$"
	hash2, err := GenerateHashFromRaw(input2)
	require.NoError(t, err)

	invalidHash := "$asdasdad$asdad"

	tests := map[string]struct {
		hash           string
		input          string
		expectedOutput bool
		err            error
	}{
		"invalid_input": {
			hash:           hash,
			input:          input2,
			expectedOutput: false,
			err:            nil,
		},
		"invalid_hash_format": {
			hash:           invalidHash,
			input:          input2,
			expectedOutput: false,
			err:            ErrInvalidHash,
		},
		"valid_input": {
			hash:           hash,
			input:          input,
			expectedOutput: true,
			err:            nil,
		},
		"valid_input_with_special_chars": {
			hash:           hash2,
			input:          input2,
			expectedOutput: true,
			err:            nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, compareErr := CompareRawAndHash(tt.input, tt.hash)

			assert.Equal(t, compareErr, tt.err)
			assert.Equal(t, tt.expectedOutput, result)
		})
	}
}
