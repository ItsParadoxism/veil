package cryptoutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

var raw = base64.RawURLEncoding

func Encode(b []byte) string { return raw.EncodeToString(b) }

func Decode(s string) ([]byte, error) { return raw.DecodeString(s) }

func GenerateIdentity() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func GenerateSecret(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

func RecoverySecret() (string, string, error) {
	b, err := GenerateSecret(32)
	if err != nil {
		return "", "", err
	}
	secret := "veil-recovery-" + Encode(b)
	h := sha256.Sum256([]byte(secret))
	return secret, Encode(h[:]), nil
}

func HashRecovery(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return Encode(h[:])
}

func ClaimProof(username, publicKey, recoveryHash string, privateKey ed25519.PrivateKey) string {
	data := strings.Join([]string{"veil-claim-v1", username, publicKey, recoveryHash}, "\n")
	return Encode(ed25519.Sign(privateKey, []byte(data)))
}

func VerifyClaim(username, publicKey, recoveryHash, proof string) bool {
	pub, err := Decode(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := Decode(proof)
	if err != nil {
		return false
	}
	data := strings.Join([]string{"veil-claim-v1", username, publicKey, recoveryHash}, "\n")
	return ed25519.Verify(ed25519.PublicKey(pub), []byte(data), sig)
}

func RecoverProof(username, newPublicKey, recoverySecret string, privateKey ed25519.PrivateKey) string {
	data := strings.Join([]string{"veil-recover-v1", username, newPublicKey, recoverySecret}, "\n")
	return Encode(ed25519.Sign(privateKey, []byte(data)))
}

func VerifyRecoverProof(username, newPublicKey, recoverySecret, proof string) bool {
	pub, err := Decode(newPublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := Decode(proof)
	if err != nil {
		return false
	}
	data := strings.Join([]string{"veil-recover-v1", username, newPublicKey, recoverySecret}, "\n")
	return ed25519.Verify(ed25519.PublicKey(pub), []byte(data), sig)
}

func RequestPayload(method, path, timestamp, nonce string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%x", method, path, timestamp, nonce, h))
}

func Encrypt(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = GenerateSecret(aead.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

func Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func MessageAAD(sessionID, sender, messageID string, sentAt int64) []byte {
	return []byte(fmt.Sprintf("veil-message-v1\n%s\n%s\n%s\n%d", sessionID, sender, messageID, sentAt))
}
