package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
)

func getMasterSecret() []byte {
	key := os.Getenv("AIMATOS_MASTER_KEY")
	if key == "" {
		return []byte("AimatosSecureDefaultPassphr32B!")
	}
	b := []byte(key)
	if len(b) < 32 {
		padded := make([]byte, 32)
		copy(padded, b)
		return padded
	}
	return b[:32]
}
func EncryptValue(plaintext string) (string, error) {
	block, err := aes.NewCipher(getMasterSecret())
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
func DecryptValue(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(getMasterSecret())
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("invalid ciphertext length")
	}

	nonce, encryptedPayload := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}