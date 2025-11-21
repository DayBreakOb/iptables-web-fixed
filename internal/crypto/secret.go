package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log"
)

var key []byte

func Init(masterKeyB64 string) error {
	b, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil {
		return err
	}
	if len(b) != 32 {
		return errors.New("MASTER_KEY must be base64(32 bytes)")
	}
	key = b
	return nil
}

func Seal(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func Open(cipherB64 string) (string, error) {
	if cipherB64 == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	n := aead.NonceSize()
	if len(raw) < n {
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := raw[:n], raw[n:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func MustOpen(cipherB64 string) string {
	s, err := Open(cipherB64)
	if err != nil {
		log.Printf("[crypto] decrypt failed: %v", err)
		return ""
	}
	return s
}
