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
	keyBytes := []byte(key)
	plaintextBytes := []byte(plaintext)
	defer clear(keyBytes)
	defer clear(plaintextBytes)
	return EncryptBytes(keyBytes, plaintextBytes)
}

// EncryptBytes encrypts secret material without requiring callers to create
// immutable string copies. The input slices remain owned by the caller and are
// not modified. Callers should clear them as soon as they are no longer needed.
func EncryptBytes(key, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("cannot encrypt empty secret")
	}
	sum := sha256.Sum256(key)
	defer clear(sum[:])
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
	return append(nonce, gcm.Seal(nil, nonce, plaintext, nil)...), nil
}

func Decrypt(key string, ciphertext []byte) (string, error) {
	keyBytes := []byte(key)
	defer clear(keyBytes)
	plaintext, err := DecryptBytes(keyBytes, ciphertext)
	if err != nil {
		return "", err
	}
	result := string(plaintext)
	clear(plaintext)
	return result, nil
}

// DecryptBytes returns caller-owned plaintext bytes so security-sensitive
// callers can clear them after use. It preserves the same typed failure as the
// legacy string API for wrong keys and malformed or tampered ciphertext.
func DecryptBytes(key, ciphertext []byte) ([]byte, error) {
	sum := sha256.Sum256(key)
	defer clear(sum[:])
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrDecrypt)
	}
	nonce, encrypted := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	return plaintext, nil
}
