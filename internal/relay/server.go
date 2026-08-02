package relay

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/422dev/veil/internal/cryptoutil"
	"github.com/422dev/veil/internal/protocol"
)

var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,31}$`)

type Server struct {
	store   *Store
	mux     *http.ServeMux
	nonceMu sync.Mutex
	nonces  map[string]int64
}

func NewServer(store *Store) *Server {
	s := &Server{store: store, mux: http.NewServeMux(), nonces: map[string]int64{}}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.securityHeaders(s.mux) }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /v1/status", s.status)
	s.mux.HandleFunc("POST /v1/identities", s.claim)
	s.mux.HandleFunc("POST /v1/identities/recover", s.recover)
	s.mux.HandleFunc("POST /v1/sessions", s.auth(s.createSession))
	s.mux.HandleFunc("POST /v1/invites", s.auth(s.createInvite))
	s.mux.HandleFunc("POST /v1/sessions/join", s.auth(s.join))
	s.mux.HandleFunc("POST /v1/messages", s.auth(s.sendMessage))
	s.mux.HandleFunc("GET /v1/history", s.auth(s.history))
	s.mux.HandleFunc("GET /v1/members", s.auth(s.members))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return nil, false
	}
	if err := json.Unmarshal(b, dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return nil, false
	}
	return b, true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, protocol.ErrorResponse{Error: message})
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, protocol.StatusResponse{Version: protocol.Version, Status: "ok", Time: time.Now().Unix()})
}

func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	var req protocol.ClaimRequest
	if _, ok := decodeBody(w, r, &req); !ok {
		return
	}
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	if !usernamePattern.MatchString(req.Username) {
		writeError(w, http.StatusBadRequest, "username must match [a-z][a-z0-9_-]{2,31}")
		return
	}
	if !cryptoutil.VerifyClaim(req.Username, req.PublicKey, req.RecoveryHash, req.Proof) {
		writeError(w, http.StatusUnauthorized, "invalid identity proof")
		return
	}
	if err := s.store.Claim(req.Username, req.PublicKey, req.RecoveryHash); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"username": req.Username})
}

func (s *Server) recover(w http.ResponseWriter, r *http.Request) {
	var req protocol.RecoverRequest
	if _, ok := decodeBody(w, r, &req); !ok {
		return
	}
	if !cryptoutil.VerifyRecoverProof(req.Username, req.NewPublicKey, req.RecoverySecret, req.Proof) {
		writeError(w, http.StatusUnauthorized, "invalid new-key proof")
		return
	}
	if err := s.store.Recover(req.Username, cryptoutil.HashRecovery(req.RecoverySecret), req.NewPublicKey); err != nil {
		writeError(w, http.StatusUnauthorized, "recovery failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": req.Username})
}

type authedHandler func(http.ResponseWriter, *http.Request, string, []byte)

func (s *Server) auth(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.Header.Get("X-Veil-Username")
		ts := r.Header.Get("X-Veil-Timestamp")
		nonce := r.Header.Get("X-Veil-Nonce")
		sigText := r.Header.Get("X-Veil-Signature")
		unix, err := strconv.ParseInt(ts, 10, 64)
		if err != nil || time.Since(time.Unix(unix, 0)) > 2*time.Minute || time.Until(time.Unix(unix, 0)) > 2*time.Minute {
			writeError(w, http.StatusUnauthorized, "stale request")
			return
		}
		if len(nonce) < 16 || !s.takeNonce(username+":"+nonce, unix) {
			writeError(w, http.StatusUnauthorized, "replayed request")
			return
		}
		pubText, ok := s.store.PublicKey(username)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unknown identity")
			return
		}
		pub, err := cryptoutil.Decode(pubText)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid identity")
			return
		}
		sig, err := cryptoutil.Decode(sigText)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid signature")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if !ed25519.Verify(pub, cryptoutil.RequestPayload(r.Method, r.URL.RequestURI(), ts, nonce, body), sig) {
			writeError(w, http.StatusUnauthorized, "invalid signature")
			return
		}
		next(w, r, username, body)
	}
}

func (s *Server) takeNonce(key string, timestamp int64) bool {
	s.nonceMu.Lock()
	defer s.nonceMu.Unlock()
	now := time.Now().Unix()
	for k, t := range s.nonces {
		if now-t > 180 {
			delete(s.nonces, k)
		}
	}
	if _, exists := s.nonces[key]; exists {
		return false
	}
	s.nonces[key] = timestamp
	return true
}

func bodyJSON(w http.ResponseWriter, body []byte, dst any) bool {
	if err := json.Unmarshal(body, dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
}

func (s *Server) createSession(w http.ResponseWriter, _ *http.Request, username string, _ []byte) {
	id, err := s.store.CreateSession(username)
	if err != nil {
		writeError(w, 500, "could not create session")
		return
	}
	writeJSON(w, http.StatusCreated, protocol.CreateSessionResponse{SessionID: id})
}

func (s *Server) createInvite(w http.ResponseWriter, _ *http.Request, username string, body []byte) {
	var req protocol.InviteRequest
	if !bodyJSON(w, body, &req) {
		return
	}
	token, err := s.store.CreateInvite(req.SessionID, username, req.Uses, req.ExpiresAt)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, protocol.InviteResponse{Token: token})
}

func (s *Server) join(w http.ResponseWriter, _ *http.Request, username string, body []byte) {
	var req protocol.JoinRequest
	if !bodyJSON(w, body, &req) {
		return
	}
	if err := s.store.Join(req.SessionID, username, req.InviteToken); err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"session_id": req.SessionID})
}

func (s *Server) sendMessage(w http.ResponseWriter, _ *http.Request, username string, body []byte) {
	var req protocol.SendMessageRequest
	if !bodyJSON(w, body, &req) {
		return
	}
	if req.MessageID == "" || req.Nonce == "" || req.Ciphertext == "" {
		writeError(w, 400, "missing encrypted message fields")
		return
	}
	m, err := s.store.AddMessage(username, req)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request, username string, _ []byte) {
	sessionID := r.URL.Query().Get("session")
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	messages, err := s.store.History(sessionID, username, after)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.HistoryResponse{Messages: messages})
}

func (s *Server) members(w http.ResponseWriter, r *http.Request, username string, _ []byte) {
	result, err := s.store.Who(r.URL.Query().Get("session"), username)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) storeError(w http.ResponseWriter, err error) {
	if errors.Is(err, errForbidden) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

func ListenAndServe(addr, cert, key string, handler http.Handler) error {
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	if cert != "" || key != "" {
		if cert == "" || key == "" {
			return fmt.Errorf("both -tls-cert and -tls-key are required")
		}
		return server.ListenAndServeTLS(cert, key)
	}
	return server.ListenAndServe()
}
