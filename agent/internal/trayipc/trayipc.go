// Package trayipc is the local protocol between the macOS menu-bar tray
// (running as the logged-in user) and the root agent daemon.
//
// The tray is unprivileged and privacy.json is root-owned (0644, or 0444
// when an administrator locks it), so the tray cannot write it. Instead it
// sends a one-line JSON request on a Unix domain socket owned by root; the
// daemon reads the peer credentials of the connection (LOCAL_PEERCRED) and
// only accepts a privacy change from root or from the console user (the user
// in front of the screen).
//
// No build tag and stdlib only, so the protocol and the authorization
// decision are unit-tested on every OS (Go 1.20 compatible).
package trayipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// SocketDir is created by the daemon, root-owned, mode 0755.
	SocketDir = "/var/run/obliance-agent"
	// SocketPath is the listening socket (mode 0666: authorization is done
	// on the peer credentials, not on the file mode).
	SocketPath = SocketDir + "/tray.sock"

	// MaxRequestBytes bounds a request line.
	MaxRequestBytes = 1024

	OpStatus     = "status"
	OpSetPrivacy = "set_privacy"
)

// Request is one JSON line sent by the tray.
type Request struct {
	Op      string `json:"op"`
	Enabled bool   `json:"enabled,omitempty"`
}

// Response is one JSON line returned by the daemon.
type Response struct {
	OK             bool   `json:"ok"`
	Error          string `json:"error,omitempty"`
	PrivacyEnabled bool   `json:"privacyEnabled"`
	PrivacyLocked  bool   `json:"privacyLocked"`
}

// Console describes the user owning the console (/dev/console).
type Console struct {
	UID   uint32
	Known bool
}

// ErrNotAllowed is returned when the peer may not perform the operation.
var ErrNotAllowed = errors.New("only the user logged in at the console may change privacy mode")

// Authorize decides whether a peer may run op.
//   - status: read-only, any local user.
//   - set_privacy: root, or the current console user. Nobody else (other
//     users behind fast user switching, SSH sessions, daemons running as
//     service accounts). At the login window the console belongs to root,
//     so only root is accepted.
func Authorize(op string, peerUID uint32, console Console) error {
	switch op {
	case OpStatus:
		return nil
	case OpSetPrivacy:
		if peerUID == 0 {
			return nil
		}
		if console.Known && console.UID != 0 && peerUID == console.UID {
			return nil
		}
		return ErrNotAllowed
	default:
		return fmt.Errorf("unknown operation %q", op)
	}
}

// Backend is implemented by the daemon.
type Backend interface {
	Privacy() (enabled, locked bool)
	SetPrivacy(enabled bool, peerUID uint32) error
}

// Serve handles exactly one request on conn (already authenticated by the
// caller through peerUID) and writes one response. The caller closes conn
// and sets its deadline.
func Serve(conn io.ReadWriter, peerUID uint32, console Console, b Backend) Response {
	resp := handle(conn, peerUID, console, b)
	resp.PrivacyEnabled, resp.PrivacyLocked = b.Privacy()
	line, _ := json.Marshal(resp)
	_, _ = conn.Write(append(line, '\n'))
	return resp
}

func handle(conn io.Reader, peerUID uint32, console Console, b Backend) Response {
	req, err := readRequest(conn)
	if err != nil {
		return Response{Error: err.Error()}
	}
	if err := Authorize(req.Op, peerUID, console); err != nil {
		return Response{Error: err.Error()}
	}
	switch req.Op {
	case OpStatus:
		return Response{OK: true}
	case OpSetPrivacy:
		if _, locked := b.Privacy(); locked {
			return Response{Error: "privacy mode is locked by your administrator"}
		}
		if err := b.SetPrivacy(req.Enabled, peerUID); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{OK: true}
	}
	return Response{Error: "unsupported operation"}
}

func readRequest(r io.Reader) (Request, error) {
	// Read at most MaxRequestBytes+1 bytes: a line that does not end within
	// the limit is rejected without buffering more.
	br := bufio.NewReader(io.LimitReader(r, MaxRequestBytes+1))
	line, err := br.ReadBytes('\n')
	if len(line) > MaxRequestBytes {
		return Request{}, errors.New("request too large")
	}
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return Request{}, errors.New("malformed request")
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return Request{}, errors.New("malformed request")
	}
	return req, nil
}

// Call sends req to the daemon listening on socketPath and returns its
// response. A transport failure (daemon down, no socket) is returned as err;
// a refusal by the daemon is returned in Response.Error with err == nil.
func Call(socketPath string, req Request, timeout time.Duration) (Response, error) {
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	line, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return Response{}, err
	}
	return ReadResponse(conn)
}

// ReadResponse reads one response line.
func ReadResponse(r io.Reader) (Response, error) {
	br := bufio.NewReader(io.LimitReader(r, 64*1024))
	line, err := br.ReadBytes('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return Response{}, err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, fmt.Errorf("malformed response: %w", err)
	}
	return resp, nil
}
