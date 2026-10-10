package trayipc

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestAuthorize(t *testing.T) {
	console501 := Console{UID: 501, Known: true}
	loginWindow := Console{UID: 0, Known: true}
	unknown := Console{}
	cases := []struct {
		name    string
		op      string
		peer    uint32
		console Console
		ok      bool
	}{
		{"status any user", OpStatus, 502, console501, true},
		{"status unknown console", OpStatus, 502, unknown, true},
		{"set by console user", OpSetPrivacy, 501, console501, true},
		{"set by root", OpSetPrivacy, 0, console501, true},
		{"set by root at login window", OpSetPrivacy, 0, loginWindow, true},
		{"set by other user", OpSetPrivacy, 502, console501, false},
		{"set by service account", OpSetPrivacy, 1, console501, false},
		{"set at login window by user", OpSetPrivacy, 501, loginWindow, false},
		{"set console unknown", OpSetPrivacy, 501, unknown, false},
		{"unknown op", "rm -rf", 0, console501, false},
		{"empty op", "", 501, console501, false},
	}
	for _, c := range cases {
		err := Authorize(c.op, c.peer, c.console)
		if (err == nil) != c.ok {
			t.Errorf("%s: Authorize(%q, %d, %+v) = %v, want ok=%v", c.name, c.op, c.peer, c.console, err, c.ok)
		}
	}
}

type fakeBackend struct {
	enabled, locked bool
	setCalls        int
	lastUID         uint32
	setErr          error
}

func (f *fakeBackend) Privacy() (bool, bool) { return f.enabled, f.locked }
func (f *fakeBackend) SetPrivacy(enabled bool, uid uint32) error {
	f.setCalls++
	f.lastUID = uid
	if f.setErr != nil {
		return f.setErr
	}
	f.enabled = enabled
	return nil
}

type rw struct {
	in  *strings.Reader
	out bytes.Buffer
}

func (r *rw) Read(p []byte) (int, error)  { return r.in.Read(p) }
func (r *rw) Write(p []byte) (int, error) { return r.out.Write(p) }

func serve(t *testing.T, req string, peer uint32, console Console, b *fakeBackend) Response {
	t.Helper()
	conn := &rw{in: strings.NewReader(req)}
	ret := Serve(conn, peer, console, b)
	got, err := ReadResponse(&conn.out)
	if err != nil {
		t.Fatalf("ReadResponse: %v (raw %q)", err, conn.out.String())
	}
	if got != ret {
		t.Fatalf("written response %+v != returned %+v", got, ret)
	}
	return got
}

func TestServeSetPrivacyConsoleUser(t *testing.T) {
	b := &fakeBackend{}
	resp := serve(t, `{"op":"set_privacy","enabled":true}`+"\n", 501, Console{UID: 501, Known: true}, b)
	if !resp.OK || !resp.PrivacyEnabled || b.setCalls != 1 || b.lastUID != 501 {
		t.Fatalf("unexpected: resp=%+v backend=%+v", resp, b)
	}
}

func TestServeSetPrivacyOtherUserRefused(t *testing.T) {
	b := &fakeBackend{}
	resp := serve(t, `{"op":"set_privacy","enabled":true}`+"\n", 502, Console{UID: 501, Known: true}, b)
	if resp.OK || resp.Error == "" || b.setCalls != 0 || resp.PrivacyEnabled {
		t.Fatalf("other user must be refused: resp=%+v backend=%+v", resp, b)
	}
}

func TestServeLockedRefused(t *testing.T) {
	b := &fakeBackend{enabled: true, locked: true}
	resp := serve(t, `{"op":"set_privacy","enabled":false}`+"\n", 501, Console{UID: 501, Known: true}, b)
	if resp.OK || b.setCalls != 0 || !resp.PrivacyEnabled || !resp.PrivacyLocked {
		t.Fatalf("locked privacy must be refused: resp=%+v backend=%+v", resp, b)
	}
}

func TestServeBackendError(t *testing.T) {
	b := &fakeBackend{setErr: errors.New("boom")}
	resp := serve(t, `{"op":"set_privacy","enabled":true}`, 0, Console{}, b)
	if resp.OK || resp.Error != "boom" {
		t.Fatalf("backend error not reported: %+v", resp)
	}
}

func TestServeStatus(t *testing.T) {
	b := &fakeBackend{enabled: true}
	resp := serve(t, `{"op":"status"}`+"\n", 777, Console{UID: 501, Known: true}, b)
	if !resp.OK || !resp.PrivacyEnabled || b.setCalls != 0 {
		t.Fatalf("status: %+v", resp)
	}
}

func TestServeMalformedAndOversized(t *testing.T) {
	for _, req := range []string{
		"not json\n",
		"",
		`{"op":"set_privacy","enabled":true,"pad":"` + strings.Repeat("x", MaxRequestBytes) + `"}` + "\n",
	} {
		b := &fakeBackend{}
		resp := serve(t, req, 0, Console{}, b)
		if resp.OK || b.setCalls != 0 {
			t.Errorf("request %.40q must be rejected: %+v", req, resp)
		}
	}
}
