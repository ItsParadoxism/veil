package cryptoutil

import "testing"

func TestEncryptRoundTripAndTamper(t *testing.T) {
	key, err := GenerateSecret(32)
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := Encrypt(key, []byte("private line"), []byte("context"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Decrypt(key, nonce, ciphertext, []byte("context"))
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "private line" {
		t.Fatalf("got %q", plain)
	}
	ciphertext[0] ^= 1
	if _, err := Decrypt(key, nonce, ciphertext, []byte("context")); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
}
