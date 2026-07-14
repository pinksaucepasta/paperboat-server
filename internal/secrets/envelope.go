package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// ErrDecrypt wraps every failure to decrypt a stored secret (wrong key, tampered
// or truncated ciphertext). Callers can use errors.Is to detect it — e.g. so
// project teardown can proceed even when a secret was encrypted under a key that
// is no longer configured.
var ErrDecrypt = errors.New("secret decryption failed")

func Encrypt(key string, plaintext string) ([]byte, error) {
	if plaintext == "" {
		return nil, errors.New("cannot encrypt empty secret")
	}
	sum := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, []byte(plaintext), nil)...), nil
}

func Decrypt(key string, ciphertext []byte) (string, error) {
	sum := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", fmt.Errorf("%w: ciphertext too short", ErrDecrypt)
	}
	nonce, encrypted := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	return string(plaintext), nil
}
