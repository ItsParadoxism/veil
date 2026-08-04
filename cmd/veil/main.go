package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/422dev/veil/internal/client"
	"github.com/422dev/veil/internal/cryptoutil"
	"github.com/422dev/veil/internal/protocol"
)

const defaultRelay = "http://127.0.0.1:7443"

type app struct {
	statePath string
	state     protocol.ClientState
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "veil:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	statePath, err := client.DefaultStatePath()
	if err != nil {
		return err
	}
	state, err := client.LoadState(statePath)
	if err != nil {
		return err
	}
	a := &app{statePath: statePath, state: state}
	if len(args) == 0 {
		return a.chat(nil)
	}
	switch args[0] {
	case "claim":
		return a.claim(args[1:])
	case "recover":
		return a.recover(args[1:])
	case "create":
		return a.create(args[1:])
	case "join":
		return a.join(args[1:])
	case "invite":
		return a.invite(args[1:])
	case "chat":
		return a.chat(args[1:])
	case "send":
		return a.sendCommand(args[1:])
	case "who":
		return a.who(args[1:])
	case "sessions":
		return a.sessions()
	case "status":
		return a.status(args[1:])
	case "version", "--version", "-v":
		fmt.Println("veil/" + protocol.Version)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Print(`veil/0.1 — private communication. nothing more.

usage:
  veil claim [--relay URL] <username>
  veil recover [--relay URL] <username> <recovery-secret>
  veil create [--relay URL]
  veil join <invite>
  veil chat [session]
  veil send [--session ID] <message>
  veil invite [--session ID] [--uses N] [--expires 10m]
  veil who [--session ID]
  veil sessions
  veil status [--relay URL]
`)
}

func (a *app) recover(args []string) error {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	relayURL := fs.String("relay", relayDefault(), "relay URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: veil recover [--relay URL] <username> <recovery-secret>")
	}
	username, recoverySecret := strings.ToLower(fs.Arg(0)), fs.Arg(1)
	pub, priv, err := cryptoutil.GenerateIdentity()
	if err != nil {
		return err
	}
	pubText := cryptoutil.Encode(pub)
	req := protocol.RecoverRequest{Username: username, RecoverySecret: recoverySecret, NewPublicKey: pubText, Proof: cryptoutil.RecoverProof(username, pubText, recoverySecret, priv)}
	if err := client.NewAPI(*relayURL).Do(http.MethodPost, "/v1/identities/recover", req, nil, false); err != nil {
		return err
	}
	a.state.Identity = &protocol.Identity{Username: username, PublicKey: pubText, PrivateKey: cryptoutil.Encode(priv)}
	if err := client.SaveState(a.statePath, a.state); err != nil {
		return fmt.Errorf("identity recovered but local key could not be saved: %w", err)
	}
	fmt.Printf("identity recovered: %s\n", username)
	return nil
}

func relayDefault() string {
	if v := os.Getenv("VEIL_RELAY"); v != "" {
		return v
	}
	return defaultRelay
}

func (a *app) claim(args []string) error {
	fs := flag.NewFlagSet("claim", flag.ContinueOnError)
	relayURL := fs.String("relay", relayDefault(), "relay URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: veil claim [--relay URL] <username>")
	}
	if a.state.Identity != nil {
		return fmt.Errorf("identity %q already exists in local state", a.state.Identity.Username)
	}
	username := strings.ToLower(fs.Arg(0))
	pub, priv, err := cryptoutil.GenerateIdentity()
	if err != nil {
		return err
	}
	recovery, recoveryHash, err := cryptoutil.RecoverySecret()
	if err != nil {
		return err
	}
	pubText := cryptoutil.Encode(pub)
	req := protocol.ClaimRequest{Username: username, PublicKey: pubText, RecoveryHash: recoveryHash, Proof: cryptoutil.ClaimProof(username, pubText, recoveryHash, priv)}
	if err := client.NewAPI(*relayURL).Claim(req); err != nil {
		return err
	}
	a.state.Identity = &protocol.Identity{Username: username, PublicKey: pubText, PrivateKey: cryptoutil.Encode(priv)}
	if err := client.SaveState(a.statePath, a.state); err != nil {
		return fmt.Errorf("identity claimed but local key could not be saved: %w", err)
	}
	fmt.Printf("VEIL IDENTITY CREATED\n\nidentity:  %s\nrecovery:  %s\n\nStore the recovery secret offline. It will not be shown again.\n", username, recovery)
	return nil
}

func (a *app) identityAPI(relayURL string) (*client.API, error) {
	api := client.NewAPI(relayURL)
	if err := api.WithIdentity(a.state.Identity); err != nil {
		return nil, err
	}
	return api, nil
}

func (a *app) create(args []string) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	relayURL := fs.String("relay", relayDefault(), "relay URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	api, err := a.identityAPI(*relayURL)
	if err != nil {
		return err
	}
	created, err := api.CreateSession()
	if err != nil {
		return err
	}
	key, err := cryptoutil.GenerateSecret(32)
	if err != nil {
		return err
	}
	local := protocol.LocalSession{ID: created.SessionID, Relay: strings.TrimRight(*relayURL, "/"), Key: cryptoutil.Encode(key), CreatedAt: time.Now().Unix()}
	a.state.Sessions[local.ID], a.state.Current = local, local.ID
	if err := client.SaveState(a.statePath, a.state); err != nil {
		return err
	}
	inv, err := api.CreateInvite(protocol.InviteRequest{SessionID: local.ID})
	if err != nil {
		return err
	}
	inviteURL, err := client.FormatInvite(local.Relay, local.ID, inv.Token, local.Key)
	if err != nil {
		return err
	}
	fmt.Printf("VEIL\n\nsession   %s\nadmin     %s\ncipher    xchacha20-poly1305\nhistory   persistent\npeers     1\n\ninvite:\n%s\n", local.ID, a.state.Identity.Username, inviteURL)
	return nil
}

func (a *app) join(args []string) error {
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: veil join <invite>")
	}
	inv, err := client.ParseInvite(fs.Arg(0))
	if err != nil {
		return err
	}
	key, err := cryptoutil.Decode(inv.Key)
	if err != nil || len(key) != 32 {
		return errors.New("invite contains an invalid session key")
	}
	api, err := a.identityAPI(inv.Relay)
	if err != nil {
		return err
	}
	fmt.Println("connecting...")
	if err := api.Join(protocol.JoinRequest{SessionID: inv.SessionID, InviteToken: inv.Token}); err != nil {
		return err
	}
	a.state.Sessions[inv.SessionID] = protocol.LocalSession{ID: inv.SessionID, Relay: inv.Relay, Key: inv.Key, CreatedAt: time.Now().Unix()}
	a.state.Current = inv.SessionID
	if err := client.SaveState(a.statePath, a.state); err != nil {
		return err
	}
	fmt.Println("identity verified.\nsession authenticated.\nhistory ready.")
	return nil
}

func (a *app) selected(id string) (protocol.LocalSession, error) {
	if id == "" {
		id = a.state.Current
	}
	if id == "" {
		return protocol.LocalSession{}, errors.New("no session selected; create or join one first")
	}
	s, ok := a.state.Sessions[id]
	if !ok {
		return protocol.LocalSession{}, fmt.Errorf("unknown local session %q", id)
	}
	return s, nil
}

func (a *app) invite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	sessionID := fs.String("session", "", "session ID")
	uses := fs.Int("uses", 0, "maximum uses (0 is unlimited)")
	expires := fs.Duration("expires", 0, "expiry duration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	sess, err := a.selected(*sessionID)
	if err != nil {
		return err
	}
	api, err := a.identityAPI(sess.Relay)
	if err != nil {
		return err
	}
	var expiresAt int64
	if *expires > 0 {
		expiresAt = time.Now().Add(*expires).Unix()
	}
	result, err := api.CreateInvite(protocol.InviteRequest{SessionID: sess.ID, Uses: *uses, ExpiresAt: expiresAt})
	if err != nil {
		return err
	}
	inviteURL, err := client.FormatInvite(sess.Relay, sess.ID, result.Token, sess.Key)
	if err != nil {
		return err
	}
	fmt.Println(inviteURL)
	return nil
}

func (a *app) sendCommand(args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	sessionID := fs.String("session", "", "session ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("usage: veil send [--session ID] <message>")
	}
	sess, err := a.selected(*sessionID)
	if err != nil {
		return err
	}
	return a.send(sess, strings.Join(fs.Args(), " "))
}

func (a *app) send(sess protocol.LocalSession, text string) error {
	key, err := cryptoutil.Decode(sess.Key)
	if err != nil {
		return err
	}
	idBytes, err := cryptoutil.GenerateSecret(12)
	if err != nil {
		return err
	}
	messageID, sentAt := cryptoutil.Encode(idBytes), time.Now().UnixMilli()
	aad := cryptoutil.MessageAAD(sess.ID, a.state.Identity.Username, messageID, sentAt)
	nonce, ciphertext, err := cryptoutil.Encrypt(key, []byte(text), aad)
	if err != nil {
		return err
	}
	api, err := a.identityAPI(sess.Relay)
	if err != nil {
		return err
	}
	return api.Send(protocol.SendMessageRequest{SessionID: sess.ID, MessageID: messageID, Nonce: cryptoutil.Encode(nonce), Ciphertext: cryptoutil.Encode(ciphertext), SentAt: sentAt})
}

func (a *app) who(args []string) error {
	fs := flag.NewFlagSet("who", flag.ContinueOnError)
	sessionID := fs.String("session", "", "session ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	sess, err := a.selected(*sessionID)
	if err != nil {
		return err
	}
	api, err := a.identityAPI(sess.Relay)
	if err != nil {
		return err
	}
	who, err := api.Who(sess.ID)
	if err != nil {
		return err
	}
	for _, member := range who.Members {
		role := "member"
		if member == who.Admin {
			role = "admin"
		}
		fmt.Printf("%-32s %s\n", member, role)
	}
	return nil
}

func (a *app) sessions() error {
	ids := make([]string, 0, len(a.state.Sessions))
	for id := range a.state.Sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		marker := " "
		if id == a.state.Current {
			marker = "*"
		}
		fmt.Printf("%s %-12s %s\n", marker, id, a.state.Sessions[id].Relay)
	}
	return nil
}

func (a *app) status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	relayURL := fs.String("relay", relayDefault(), "relay URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	api := client.NewAPI(*relayURL)
	var out protocol.StatusResponse
	if err := api.Do(http.MethodGet, "/v1/status", nil, &out, false); err != nil {
		return err
	}
	fmt.Printf("relay    %s\nstatus   %s\nversion  %s\n", *relayURL, out.Status, out.Version)
	return nil
}

func (a *app) chat(args []string) error {
	fs := flag.NewFlagSet("chat", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	id := ""
	if fs.NArg() > 0 {
		id = fs.Arg(0)
	}
	sess, err := a.selected(id)
	if err != nil {
		return err
	}
	if a.state.Identity == nil {
		return errors.New("no local identity")
	}
	key, err := cryptoutil.Decode(sess.Key)
	if err != nil {
		return err
	}
	api, err := a.identityAPI(sess.Relay)
	if err != nil {
		return err
	}
	who, err := api.Who(sess.ID)
	if err != nil {
		return err
	}
	a.state.Current = sess.ID
	_ = client.SaveState(a.statePath, a.state)
	fmt.Printf("veil/%s\n────────────────────────────────────────\nidentity   %s\nsession    %s\npeers      %d\ncipher     xchacha20-poly1305\nhistory    persistent\n────────────────────────────────────────\n", protocol.Version, a.state.Identity.Username, sess.ID, len(who.Members))

	var outputMu sync.Mutex
	stop := make(chan struct{})
	done := make(chan struct{})
	var lastSeen = sess.LastSeen
	go func() {
		defer close(done)
		ticker := time.NewTicker(900 * time.Millisecond)
		defer ticker.Stop()
		for {
			history, fetchErr := api.History(sess.ID, lastSeen)
			if fetchErr == nil {
				for _, m := range history.Messages {
					plain, decErr := decryptMessage(key, m)
					outputMu.Lock()
					if decErr != nil {
						fmt.Printf("\n%s  %-12s [unable to decrypt]\n> ", formatTime(m.SentAt), m.Sender)
					} else {
						fmt.Printf("\n%s  %-12s %s\n> ", formatTime(m.SentAt), m.Sender, plain)
					}
					outputMu.Unlock()
					if m.Sequence > lastSeen {
						lastSeen = m.Sequence
					}
				}
			}
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024), 1<<20)
	for {
		outputMu.Lock()
		fmt.Print("\n> ")
		outputMu.Unlock()
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "/leave" || line == "/quit" {
			break
		}
		if line == "/help" {
			fmt.Println("/help  /who  /invite  /clear  /leave")
			continue
		}
		if line == "/clear" {
			fmt.Print("\033[2J\033[H")
			continue
		}
		if line == "/who" {
			_ = a.who([]string{"--session", sess.ID})
			continue
		}
		if line == "/invite" {
			_ = a.invite([]string{"--session", sess.ID})
			continue
		}
		if strings.HasPrefix(line, "/") {
			fmt.Println("unknown command; use /help")
			continue
		}
		if err := a.send(sess, line); err != nil {
			fmt.Fprintln(os.Stderr, "send:", err)
		}
	}
	close(stop)
	<-done
	sess.LastSeen = lastSeen
	a.state.Sessions[sess.ID] = sess
	return client.SaveState(a.statePath, a.state)
}

func decryptMessage(key []byte, m protocol.Message) (string, error) {
	nonce, err := cryptoutil.Decode(m.Nonce)
	if err != nil {
		return "", err
	}
	ciphertext, err := cryptoutil.Decode(m.Ciphertext)
	if err != nil {
		return "", err
	}
	plain, err := cryptoutil.Decrypt(key, nonce, ciphertext, cryptoutil.MessageAAD(m.SessionID, m.Sender, m.MessageID, m.SentAt))
	return string(plain), err
}

func formatTime(ms int64) string { return time.UnixMilli(ms).Local().Format("15:04") }
