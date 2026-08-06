package relay

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/422dev/veil/internal/client"
	"github.com/422dev/veil/internal/cryptoutil"
	"github.com/422dev/veil/internal/protocol"
)

func testIdentity(t *testing.T, api *client.API, username string) protocol.Identity {
	t.Helper()
	pub, priv, err := cryptoutil.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, recoveryHash, err := cryptoutil.RecoverySecret()
	if err != nil {
		t.Fatal(err)
	}
	pubText := cryptoutil.Encode(pub)
	req := protocol.ClaimRequest{Username: username, PublicKey: pubText, RecoveryHash: recoveryHash, Proof: cryptoutil.ClaimProof(username, pubText, recoveryHash, priv)}
	if err := api.Claim(req); err != nil {
		t.Fatal(err)
	}
	return protocol.Identity{Username: username, PublicKey: pubText, PrivateKey: cryptoutil.Encode(priv)}
}

func TestEncryptedMessageFlow(t *testing.T) {
	dataPath := filepath.Join(t.TempDir(), "relay.json")
	store, err := OpenStore(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewServer(store).Handler())
	defer server.Close()

	anonymous := client.NewAPI(server.URL)
	aliceID := testIdentity(t, anonymous, "alice")
	bobID := testIdentity(t, anonymous, "bob")
	alice := client.NewAPI(server.URL)
	if err := alice.WithIdentity(&aliceID); err != nil {
		t.Fatal(err)
	}
	bob := client.NewAPI(server.URL)
	if err := bob.WithIdentity(&bobID); err != nil {
		t.Fatal(err)
	}

	created, err := alice.CreateSession()
	if err != nil {
		t.Fatal(err)
	}
	invite, err := alice.CreateInvite(protocol.InviteRequest{SessionID: created.SessionID, Uses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := bob.Join(protocol.JoinRequest{SessionID: created.SessionID, InviteToken: invite.Token}); err != nil {
		t.Fatal(err)
	}

	key, err := cryptoutil.GenerateSecret(32)
	if err != nil {
		t.Fatal(err)
	}
	messageID, sentAt := "msg-1", time.Now().UnixMilli()
	nonce, ciphertext, err := cryptoutil.Encrypt(key, []byte("meet at eight"), cryptoutil.MessageAAD(created.SessionID, "alice", messageID, sentAt))
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.Send(protocol.SendMessageRequest{SessionID: created.SessionID, MessageID: messageID, Nonce: cryptoutil.Encode(nonce), Ciphertext: cryptoutil.Encode(ciphertext), SentAt: sentAt}); err != nil {
		t.Fatal(err)
	}
	history, err := bob.History(created.SessionID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(history.Messages) != 1 {
		t.Fatalf("got %d messages", len(history.Messages))
	}
	m := history.Messages[0]
	decodedNonce, _ := cryptoutil.Decode(m.Nonce)
	decodedCiphertext, _ := cryptoutil.Decode(m.Ciphertext)
	plain, err := cryptoutil.Decrypt(key, decodedNonce, decodedCiphertext, cryptoutil.MessageAAD(m.SessionID, m.Sender, m.MessageID, m.SentAt))
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "meet at eight" {
		t.Fatalf("got %q", plain)
	}

	disk, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(disk), "meet at eight") {
		t.Fatal("relay persisted plaintext")
	}
}
