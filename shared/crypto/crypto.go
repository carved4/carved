package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

var Key []byte

func SetKey(hexKey string) error {
	k, err := hex.DecodeString(hexKey)
	if err != nil {
		return err
	}
	if len(k) != 32 {
		return errors.New("key must be 32 bytes (64 hex chars)")
	}
	Key = k
	return nil
}

func Encrypt(plaintext []byte) ([]byte, error) {
	if len(Key) == 0 {
		return plaintext, nil
	}

	block, err := aes.NewCipher(Key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func Decrypt(ciphertext []byte) ([]byte, error) {
	if len(Key) == 0 {
		return ciphertext, nil
	}

	block, err := aes.NewCipher(Key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

