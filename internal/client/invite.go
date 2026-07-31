package client

import (
	"fmt"
	"net/url"
	"strings"
)

type Invite struct{ Relay, SessionID, Token, Key string }

func FormatInvite(relay, sessionID, token, key string) (string, error) {
	u, err := url.Parse(relay)
	if err != nil {
		return "", err
	}
	scheme := "veil"
	if u.Scheme == "http" {
		scheme = "veil+http"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("relay URL must use http or https")
	}
	return fmt.Sprintf("%s://%s/%s#%s.%s", scheme, u.Host, sessionID, token, key), nil
}

func ParseInvite(raw string) (Invite, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Invite{}, err
	}
	relayScheme := "https"
	if u.Scheme == "veil+http" {
		relayScheme = "http"
	} else if u.Scheme != "veil" {
		return Invite{}, fmt.Errorf("invite must start with veil:// or veil+http://")
	}
	parts := strings.SplitN(u.Fragment, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Invite{}, fmt.Errorf("invite secret is invalid")
	}
	sessionID := strings.Trim(u.Path, "/")
	if sessionID == "" || u.Host == "" {
		return Invite{}, fmt.Errorf("invite address is invalid")
	}
	return Invite{Relay: relayScheme + "://" + u.Host, SessionID: sessionID, Token: parts[0], Key: parts[1]}, nil
}
