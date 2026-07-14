package encrypt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	memory      uint32 = 64 * 1024 //Costly if set too high
	iterations  uint32 = 3         //Costly if set too high
	parallelism uint8  = 2
	saltLength  uint32 = 16
	keyLength   uint32 = 32
)

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)

type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

// GenerateHashFromStr Return a string using the standard encoded hash representation. This is a string with all the
// hash base64 encoded, salt base64 encoded and all the involved params to generate the hash.
// This is an example output:
// $argon2id$v=19$m=65536,t=3,p=2$Woo1mErn1s7AHf96ewQ8Uw$D4TzIwGO4XD2buk96qAP+Ed2baMo/KbTRMqXX00wtsU
func GenerateHashFromRaw(raw string) (encodedHash string, err error) {
	salt, err := generateRandomBytes(saltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(raw), salt, iterations, memory, parallelism, keyLength)

	// Base64 encode the salt and hashed raw.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Return a string using the standard encoded hash representation.
	// This is a string representation of the algorithm and the parameters used to create the hash,
	// so it can be reproduced later.
	// Each $ prefix represents a value of interest. If we split this by the $ char:
	// pos[0] is an empty string
	// pos[1] represents the algorithm (argon2id)
	// pos[2] represents the version of argon2
	// pos[3] represents the memory(m), iteration(t), parallelism(p)
	// post[4] represents the salt base64 encoded
	// pos[5] represents the hashed raw base64 encoded
	encodedHash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, iterations, parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func CompareRawAndHash(raw, encodedHash string) (match bool, err error) {
	// Extract the parameters, salt and derived key from the encoded raw string
	// hash.
	p, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Derive the key from the other raw using the same parameters.
	otherHash := argon2.IDKey([]byte(raw), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// Check that the contents of the hashed raws are identical. Note
	// that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks.
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}

func decodeHash(encodedHash string) (p *params, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")

	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = &params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.saltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.keyLength = uint32(len(hash))

	return p, salt, hash, nil
}
