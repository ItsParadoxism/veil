package protocol

import "time"

// Version is replaced from the release tag at build time.
var Version = "dev"

type ErrorResponse struct {
	Error string `json:"error"`
}

type ClaimRequest struct {
	Username     string `json:"username"`
	PublicKey    string `json:"public_key"`
	RecoveryHash string `json:"recovery_hash"`
	Proof        string `json:"proof"`
}

type RecoverRequest struct {
	Username       string `json:"username"`
	RecoverySecret string `json:"recovery_secret"`
	NewPublicKey   string `json:"new_public_key"`
	Proof          string `json:"proof"`
}

type CreateSessionResponse struct {
	SessionID string `json:"session_id"`
}

type InviteRequest struct {
	SessionID string `json:"session_id"`
	Uses      int    `json:"uses,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

type InviteResponse struct {
	Token string `json:"token"`
}

type JoinRequest struct {
	SessionID   string `json:"session_id"`
	InviteToken string `json:"invite_token"`
}

type SendMessageRequest struct {
	SessionID  string `json:"session_id"`
	MessageID  string `json:"message_id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	SentAt     int64  `json:"sent_at"`
}

type Message struct {
	Sequence   uint64 `json:"sequence"`
	SessionID  string `json:"session_id"`
	Sender     string `json:"sender"`
	MessageID  string `json:"message_id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	SentAt     int64  `json:"sent_at"`
}

type HistoryResponse struct {
	Messages []Message `json:"messages"`
}

type WhoResponse struct {
	Admin   string   `json:"admin"`
	Members []string `json:"members"`
}

type StatusResponse struct {
	Version string `json:"version"`
	Status  string `json:"status"`
	Time    int64  `json:"time"`
}

type Identity struct {
	Username   string `json:"username"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type LocalSession struct {
	ID        string `json:"id"`
	Relay     string `json:"relay"`
	Key       string `json:"key"`
	LastSeen  uint64 `json:"last_seen"`
	CreatedAt int64  `json:"created_at"`
}

type ClientState struct {
	Identity *Identity               `json:"identity,omitempty"`
	Sessions map[string]LocalSession `json:"sessions"`
	Current  string                  `json:"current,omitempty"`
}

func UnixNow() int64 { return time.Now().Unix() }
