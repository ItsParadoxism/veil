package client

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/422dev/veil/internal/cryptoutil"
	"github.com/422dev/veil/internal/protocol"
)

type API struct {
	BaseURL    string
	Username   string
	PrivateKey ed25519.PrivateKey
	HTTP       *http.Client
}

func NewAPI(baseURL string) *API {
	return &API{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: 35 * time.Second}}
}

func (a *API) WithIdentity(identity *protocol.Identity) error {
	if identity == nil {
		return fmt.Errorf("no local identity; run 'veil claim <username>' first")
	}
	key, err := cryptoutil.Decode(identity.PrivateKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid local private key")
	}
	a.Username, a.PrivateKey = identity.Username, ed25519.PrivateKey(key)
	return nil
}

func (a *API) Do(method, path string, input, output any, authenticated bool) error {
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequest(method, a.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "veil/"+protocol.Version)
	if authenticated {
		if len(a.PrivateKey) != ed25519.PrivateKeySize {
			return fmt.Errorf("identity is not configured")
		}
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonceBytes, err := cryptoutil.GenerateSecret(18)
		if err != nil {
			return err
		}
		nonce := cryptoutil.Encode(nonceBytes)
		sig := ed25519.Sign(a.PrivateKey, cryptoutil.RequestPayload(method, req.URL.RequestURI(), ts, nonce, body))
		req.Header.Set("X-Veil-Username", a.Username)
		req.Header.Set("X-Veil-Timestamp", ts)
		req.Header.Set("X-Veil-Nonce", nonce)
		req.Header.Set("X-Veil-Signature", cryptoutil.Encode(sig))
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("relay: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var remote protocol.ErrorResponse
		if json.Unmarshal(responseBody, &remote) == nil && remote.Error != "" {
			return fmt.Errorf("relay: %s", remote.Error)
		}
		return fmt.Errorf("relay returned %s", resp.Status)
	}
	if output != nil && len(responseBody) > 0 {
		if err := json.Unmarshal(responseBody, output); err != nil {
			return fmt.Errorf("decode relay response: %w", err)
		}
	}
	return nil
}

func (a *API) Claim(req protocol.ClaimRequest) error {
	return a.Do("POST", "/v1/identities", req, nil, false)
}
func (a *API) CreateSession() (protocol.CreateSessionResponse, error) {
	var out protocol.CreateSessionResponse
	err := a.Do("POST", "/v1/sessions", nil, &out, true)
	return out, err
}
func (a *API) CreateInvite(req protocol.InviteRequest) (protocol.InviteResponse, error) {
	var out protocol.InviteResponse
	err := a.Do("POST", "/v1/invites", req, &out, true)
	return out, err
}
func (a *API) Join(req protocol.JoinRequest) error {
	return a.Do("POST", "/v1/sessions/join", req, nil, true)
}
func (a *API) Send(req protocol.SendMessageRequest) error {
	return a.Do("POST", "/v1/messages", req, nil, true)
}
func (a *API) History(session string, after uint64) (protocol.HistoryResponse, error) {
	var out protocol.HistoryResponse
	path := "/v1/history?session=" + url.QueryEscape(session) + "&after=" + strconv.FormatUint(after, 10)
	err := a.Do("GET", path, nil, &out, true)
	return out, err
}
func (a *API) Who(session string) (protocol.WhoResponse, error) {
	var out protocol.WhoResponse
	err := a.Do("GET", "/v1/members?session="+url.QueryEscape(session), nil, &out, true)
	return out, err
}
