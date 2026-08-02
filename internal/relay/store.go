package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/422dev/veil/internal/protocol"
)

var errForbidden = errors.New("forbidden")

type userRecord struct {
	PublicKey    string `json:"public_key"`
	RecoveryHash string `json:"recovery_hash"`
	CreatedAt    int64  `json:"created_at"`
}

type inviteRecord struct {
	TokenHash string `json:"token_hash"`
	UsesLeft  int    `json:"uses_left"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Revoked   bool   `json:"revoked"`
}

type sessionRecord struct {
	Admin    string                   `json:"admin"`
	Members  map[string]bool          `json:"members"`
	Invites  map[string]*inviteRecord `json:"invites"`
	Messages []protocol.Message       `json:"messages"`
	Closed   bool                     `json:"closed"`
}

type diskState struct {
	Users    map[string]*userRecord    `json:"users"`
	Sessions map[string]*sessionRecord `json:"sessions"`
}

type Store struct {
	mu    sync.RWMutex
	path  string
	state diskState
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, state: diskState{Users: map[string]*userRecord{}, Sessions: map[string]*sessionRecord{}}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.state); err != nil {
		return nil, fmt.Errorf("decode relay data: %w", err)
	}
	if s.state.Users == nil {
		s.state.Users = map[string]*userRecord{}
	}
	if s.state.Sessions == nil {
		s.state.Sessions = map[string]*sessionRecord{}
	}
	return s, nil
}

func (s *Store) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) Claim(username, publicKey, recoveryHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Users[username]; ok {
		return errors.New("username already claimed")
	}
	s.state.Users[username] = &userRecord{PublicKey: publicKey, RecoveryHash: recoveryHash, CreatedAt: time.Now().Unix()}
	return s.persistLocked()
}

func (s *Store) PublicKey(username string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.state.Users[username]
	if !ok {
		return "", false
	}
	return u.PublicKey, true
}

func (s *Store) Recover(username, recoveryHash, newPublicKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.state.Users[username]
	if !ok {
		return errors.New("identity not found")
	}
	if u.RecoveryHash != recoveryHash {
		return errForbidden
	}
	u.PublicKey = newPublicKey
	return s.persistLocked()
}

func randomCode(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (s *Store) CreateSession(admin string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		id, err := randomCode(6)
		if err != nil {
			return "", err
		}
		if _, exists := s.state.Sessions[id]; exists {
			continue
		}
		s.state.Sessions[id] = &sessionRecord{Admin: admin, Members: map[string]bool{admin: true}, Invites: map[string]*inviteRecord{}, Messages: []protocol.Message{}}
		return id, s.persistLocked()
	}
}

func (s *Store) CreateInvite(sessionID, actor string, uses int, expiresAt int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.state.Sessions[sessionID]
	if !ok || sess.Closed {
		return "", errors.New("session not found")
	}
	if sess.Admin != actor {
		return "", errForbidden
	}
	if uses < 0 {
		return "", errors.New("uses cannot be negative")
	}
	token, err := randomCode(32)
	if err != nil {
		return "", err
	}
	hash := tokenHash(token)
	sess.Invites[hash] = &inviteRecord{TokenHash: hash, UsesLeft: uses, ExpiresAt: expiresAt}
	return token, s.persistLocked()
}

func (s *Store) Join(sessionID, username, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.state.Sessions[sessionID]
	if !ok || sess.Closed {
		return errors.New("session not found")
	}
	if sess.Members[username] {
		return nil
	}
	inv, ok := sess.Invites[tokenHash(token)]
	if !ok || inv.Revoked {
		return errForbidden
	}
	if inv.ExpiresAt != 0 && time.Now().Unix() > inv.ExpiresAt {
		return errors.New("invite expired")
	}
	if inv.UsesLeft < 0 {
		return errForbidden
	}
	if inv.UsesLeft > 0 {
		inv.UsesLeft--
		if inv.UsesLeft == 0 {
			inv.Revoked = true
		}
	}
	sess.Members[username] = true
	return s.persistLocked()
}

func (s *Store) AddMessage(username string, req protocol.SendMessageRequest) (protocol.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.state.Sessions[req.SessionID]
	if !ok || sess.Closed {
		return protocol.Message{}, errors.New("session not found")
	}
	if !sess.Members[username] {
		return protocol.Message{}, errForbidden
	}
	m := protocol.Message{Sequence: uint64(len(sess.Messages) + 1), SessionID: req.SessionID, Sender: username, MessageID: req.MessageID, Nonce: req.Nonce, Ciphertext: req.Ciphertext, SentAt: req.SentAt}
	sess.Messages = append(sess.Messages, m)
	return m, s.persistLocked()
}

func (s *Store) History(sessionID, username string, after uint64) ([]protocol.Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.state.Sessions[sessionID]
	if !ok || sess.Closed {
		return nil, errors.New("session not found")
	}
	if !sess.Members[username] {
		return nil, errForbidden
	}
	if after >= uint64(len(sess.Messages)) {
		return []protocol.Message{}, nil
	}
	out := append([]protocol.Message(nil), sess.Messages[after:]...)
	return out, nil
}

func (s *Store) Who(sessionID, username string) (protocol.WhoResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.state.Sessions[sessionID]
	if !ok || !sess.Members[username] {
		return protocol.WhoResponse{}, errForbidden
	}
	members := make([]string, 0, len(sess.Members))
	for member := range sess.Members {
		members = append(members, member)
	}
	sort.Strings(members)
	return protocol.WhoResponse{Admin: sess.Admin, Members: members}, nil
}
