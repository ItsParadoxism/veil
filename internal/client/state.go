package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/422dev/veil/internal/protocol"
)

func DefaultStatePath() (string, error) {
	if path := os.Getenv("VEIL_STATE"); path != "" {
		return path, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "veil", "state.json"), nil
}

func LoadState(path string) (protocol.ClientState, error) {
	state := protocol.ClientState{Sessions: map[string]protocol.LocalSession{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(b, &state); err != nil {
		return state, fmt.Errorf("decode client state: %w", err)
	}
	if state.Sessions == nil {
		state.Sessions = map[string]protocol.LocalSession{}
	}
	return state, nil
}

func SaveState(path string, state protocol.ClientState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
