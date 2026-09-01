package secrets

import (
	"bytes"
	"errors"
	"testing"
)

func TestByteEnvelopeRoundTripAndTamper(t *testing.T) {
	key := []byte("paperboat-test-envelope-key-0123456789")
	plaintext := []byte("sensitive certificate private key")
	wantKey := append([]byte(nil), key...)
	wantPlaintext := append([]byte(nil), plaintext...)

	ciphertext, err := EncryptBytes(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ciphertext, plaintext) || !bytes.Equal(key, wantKey) || !bytes.Equal(plaintext, wantPlaintext) {
		t.Fatal("byte envelope exposed or modified caller-owned input")
	}
	opened, err := DecryptBytes(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened plaintext = %q", opened)
	}
	clear(opened)

	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 1
	if _, err := DecryptBytes(key, tampered); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered ciphertext error = %v", err)
	}
}

func TestByteEnvelopeRejectsEmptyPlaintext(t *testing.T) {
	if _, err := EncryptBytes([]byte("paperboat-test-envelope-key-0123456789"), nil); err == nil {
		t.Fatal("empty plaintext was accepted")
	}
}

func TestLegacyEnvelopeCompatibility(t *testing.T) {
	const key = "paperboat-test-envelope-key-0123456789"
	const plaintext = "legacy secret"
	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if opened != plaintext {
		t.Fatalf("opened plaintext = %q", opened)
	}
}
