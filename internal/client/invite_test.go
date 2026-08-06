package client

import "testing"

func TestInviteRoundTrip(t *testing.T) {
	raw, err := FormatInvite("http://127.0.0.1:7443", "session", "token", "key")
	if err != nil {
		t.Fatal(err)
	}
	invite, err := ParseInvite(raw)
	if err != nil {
		t.Fatal(err)
	}
	if invite.Relay != "http://127.0.0.1:7443" || invite.SessionID != "session" || invite.Token != "token" || invite.Key != "key" {
		t.Fatalf("unexpected invite: %+v", invite)
	}
}

func TestInviteRejectsMissingSecret(t *testing.T) {
	if _, err := ParseInvite("veil://relay.example/session"); err == nil {
		t.Fatal("accepted invite without secret")
	}
}
