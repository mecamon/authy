package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"testing"
)

var to *TokenServ

func TestMain(m *testing.M) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	to = New(privKey)

	code := m.Run()
	os.Exit(code)
}
