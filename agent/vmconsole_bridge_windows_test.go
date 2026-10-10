//go:build windows

package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A fake helper speaking the vmconsole stdout protocol (protocol 2): status,
// init, one frame; every stdin line is logged; "sas" makes it end with
// other_connection (exit 7), stdin EOF ends it normally.
const fakeHelperSrc = `package main

import (
	"bufio"
	"encoding/binary"
	"os"
	"strconv"
	"strings"
)

func frame(t byte, p []byte) {
	h := make([]byte, 5)
	h[0] = t
	binary.LittleEndian.PutUint32(h[1:], uint32(len(p)))
	os.Stdout.Write(append(h, p...))
}

func main() {
	logf, _ := os.OpenFile(os.Getenv("VMC_FAKE_LOG"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	logf.WriteString("ARGS " + strings.Join(os.Args[1:], " ") + "\n")
	if c := os.Getenv("VMC_FAKE_EXIT"); c != "" {
		n, _ := strconv.ParseUint(c, 0, 32)
		logf.Close()
		os.Exit(int(n))
	}
	frame('S', []byte(` + "`" + `{"state":"connecting"}` + "`" + `))
	wh := make([]byte, 8)
	binary.LittleEndian.PutUint32(wh[0:], 640)
	binary.LittleEndian.PutUint32(wh[4:], 480)
	frame('I', wh)
	frame('S', []byte(` + "`" + `{"state":"connected","width":640,"height":480,"unicode":false}` + "`" + `))
	frame('F', []byte{0, 0, 0, 1, 0x65, 0x88})
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		logf.WriteString(line + "\n")
		if strings.Contains(line, ` + "`" + `"type":"sas"` + "`" + `) {
			frame('S', []byte(` + "`" + `{"state":"ended","code":"other_connection","message":"Another connection took the console","error":"0x00000005"}` + "`" + `))
			logf.Close()
			os.Exit(7)
		}
	}
	logf.Close()
}
`

func buildFakeHelper(t *testing.T, dir string) {
	t.Helper()
	src := t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "go.mod"), []byte("module fakevmhelper\n\ngo 1.20\n"), 0o644)
	_ = os.WriteFile(filepath.Join(src, "main.go"), []byte(fakeHelperSrc), 0o644)
	cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "vmconsole.exe"), ".")
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go toolchain not usable to build the fake helper: %v\n%s", err, out)
	}
}

// relayStub accepts the agent's /api/remote/agent-tunnel/{token} WebSocket.
type relayStub struct {
	ln    net.Listener
	conns chan *wsConn
}

func newRelayStub(t *testing.T, token string) *relayStub {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rs := &relayStub{ln: ln, conns: make(chan *wsConn, 1)}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/remote/agent-tunnel/"+token || r.Header.Get("X-Api-Key") != "k" {
			w.WriteHeader(403)
			return
		}
		h := sha1.New()
		h.Write([]byte(r.Header.Get("Sec-WebSocket-Key") + wsGUID))
		accept := base64.StdEncoding.EncodeToString(h.Sum(nil))
		hj, _ := w.(http.Hijacker)
		c, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n")
		_ = brw.Flush()
		rs.conns <- &wsConn{conn: c, r: bufio.NewReader(c)}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return rs
}

// serverSend writes an UNMASKED (server) text frame.
func serverSend(t *testing.T, ws *wsConn, msg string) {
	t.Helper()
	p := []byte(msg)
	hdr := []byte{0x81}
	if len(p) < 126 {
		hdr = append(hdr, byte(len(p)))
	} else {
		hdr = append(hdr, 126, byte(len(p)>>8), byte(len(p)))
	}
	if _, err := ws.conn.Write(append(hdr, p...)); err != nil {
		t.Fatal(err)
	}
}

func TestVmConsoleBridge(t *testing.T) {
	withTestHost(t)
	savedState := vmcStateOf
	vmcStateOf = func(string) (string, error) { return "Running", nil }
	t.Cleanup(func() { vmcStateOf = savedState })

	// "Installed" helper: current.json → b-<sha12> with the fake helper.
	base := vmConsoleDir()
	sha := strings.Repeat("ab", 32)
	dir := filepath.Join(base, "b-"+sha[:12])
	_ = os.MkdirAll(dir, 0o755)
	buildFakeHelper(t, dir)
	_ = os.WriteFile(filepath.Join(dir, "vmconsole-version.txt"), []byte("protocol=2\n"), 0o644)
	cur, _ := json.Marshal(vmcCurrent{SHA256: sha, Dir: "b-" + sha[:12], Protocol: 2})
	_ = os.WriteFile(filepath.Join(base, "current.json"), cur, 0o644)
	logPath := filepath.Join(t.TempDir(), "helper.log")
	t.Setenv("VMC_FAKE_LOG", logPath)

	token := "tok123"
	rs := newRelayStub(t, token)
	// Whatever happens, the helper is stopped before the temp folder goes.
	t.Cleanup(func() {
		closeVmConsoleByToken(token)
		time.Sleep(300 * time.Millisecond)
	})
	d := &CommandDispatcher{serverURL: "http://" + rs.ln.Addr().String(), apiKey: "k"}
	vmID := "0B6A3C2E-1111-2222-3333-444455556666"

	done := make(chan error, 1)
	go func() {
		_, err := d.handleOpenVmConsole(AgentCommand{ID: "c1", Type: "open_vm_console", Payload: map[string]interface{}{
			"sessionToken": token, "vmId": vmID, "installPolicy": "manual",
		}})
		done <- err
	}()
	var ws *wsConn
	select {
	case ws = <-rs.conns:
	case <-time.After(10 * time.Second):
		t.Fatal("the agent never dialled the relay")
	}
	if err := <-done; err != nil {
		t.Fatalf("open_vm_console: %v", err)
	}

	// Agent → viewer: vm_state preparing / starting / connecting, init with
	// the vm_* features, vm_state connected, then a 0x02 H.264 frame.
	var gotInit, gotFrame bool
	states := []string{}
	deadline := time.Now().Add(10 * time.Second)
	for !(gotInit && gotFrame) && time.Now().Before(deadline) {
		_ = ws.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		op, p, err := ws.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch op {
		case 0x1:
			var m map[string]interface{}
			_ = json.Unmarshal(p, &m)
			switch m["type"] {
			case "vm_state":
				states = append(states, m["state"].(string))
			case "init":
				gotInit = true
				if m["width"].(float64) != 640 || m["codec"] != "h264" || !strings.Contains(string(p), "vm_sas") {
					t.Fatalf("init: %s", p)
				}
			}
		case 0x2:
			if p[0] != 0x02 || len(p) != 7 {
				t.Fatalf("frame: %v", p)
			}
			gotFrame = true
		}
	}
	if !gotInit || !gotFrame {
		t.Fatal("no init / frame relayed")
	}
	if strings.Join(states, ",") != "preparing,starting,connecting,connected" {
		t.Fatalf("states: %v", states)
	}

	// Viewer → helper: console input reaches stdin (sanitised), the rest does not.
	serverSend(t, ws, `{"type":"mouse","action":"move","x":10.6,"y":20,"gen":4}`)
	serverSend(t, ws, `{"type":"clipboard_set","text":"secret","id":"c1"}`)
	serverSend(t, ws, `{"type":"key","action":"down","code":"IntlBackslash","key":"<","ctrl":false}`)
	serverSend(t, ws, `{"type":"type_text","text":"héllo\nworld","layout":"0000040C"}`)
	serverSend(t, ws, `{"type":"sas"}`)

	// The helper ends with other_connection → the viewer gets the coded error.
	var gotErr map[string]interface{}
	for time.Now().Before(deadline.Add(10 * time.Second)) {
		_ = ws.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		op, p, err := ws.ReadFrame()
		if err != nil {
			break
		}
		if op == 0x1 {
			var m map[string]interface{}
			_ = json.Unmarshal(p, &m)
			if m["type"] == "error" {
				gotErr = m
				break
			}
		}
	}
	if gotErr == nil || gotErr["code"] != vmErrTaken || gotErr["retry"] != false {
		t.Fatalf("expected a vm_console_taken error, got %v", gotErr)
	}
	// The session is closed and unregistered.
	time.Sleep(300 * time.Millisecond)
	vmConsolesMu.Lock()
	n := len(vmConsoles)
	vmConsolesMu.Unlock()
	if n != 0 {
		t.Fatalf("%d console session(s) still registered", n)
	}

	logB, _ := os.ReadFile(logPath)
	log := string(logB)
	if !strings.Contains(log, "ARGS "+vmID+" - 0") {
		t.Fatalf("helper args: %s", log)
	}
	if !strings.Contains(log, `{"action":"move","type":"mouse","x":10,"y":20}`) {
		t.Fatalf("mouse line: %s", log)
	}
	if !strings.Contains(log, `"code":"IntlBackslash"`) || !strings.Contains(log, `"type":"type_text"`) || !strings.Contains(log, `"layout":"0000040C"`) {
		t.Fatalf("key / text lines: %s", log)
	}
	if strings.Contains(log, "secret") || strings.Contains(log, "clipboard") || strings.Contains(log, "gen") {
		t.Fatalf("non-console message reached the helper: %s", log)
	}
}

// A helper the Windows loader refuses (0xC0000139 entry point not found /
// 0xC0000135 DLL not found, before main) gives the viewer a coded,
// non-retryable error: vm_console_os_unsupported on NT 6.x (Server 2012),
// vm_console_start_failed elsewhere — never a bare close.
func TestVmConsoleLoaderFailure(t *testing.T) {
	cases := []struct {
		nt6  bool
		exit string
		want string
	}{
		{true, "0xC0000139", vmErrOSUnsupported},
		{true, "0xC0000135", vmErrOSUnsupported},
		{false, "0xC0000139", vmErrHelperStart},
		{false, "0xC0000135", vmErrHelperStart},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("%d-%v-%s", i, c.nt6, c.exit), func(t *testing.T) {
			withTestHost(t)
			savedState, savedNT6 := vmcStateOf, vmcHostIsNT6
			vmcStateOf = func(string) (string, error) { return "Running", nil }
			vmcHostIsNT6 = func() bool { return c.nt6 }
			t.Cleanup(func() { vmcStateOf, vmcHostIsNT6 = savedState, savedNT6 })
			base := vmConsoleDir()
			sha := strings.Repeat("cd", 32)
			dir := filepath.Join(base, "b-"+sha[:12])
			_ = os.MkdirAll(dir, 0o755)
			buildFakeHelper(t, dir)
			_ = os.WriteFile(filepath.Join(dir, "vmconsole-version.txt"), []byte("protocol=2\n"), 0o644)
			cur, _ := json.Marshal(vmcCurrent{SHA256: sha, Dir: "b-" + sha[:12], Protocol: 2})
			_ = os.WriteFile(filepath.Join(base, "current.json"), cur, 0o644)
			t.Setenv("VMC_FAKE_LOG", filepath.Join(t.TempDir(), "helper.log"))
			t.Setenv("VMC_FAKE_EXIT", c.exit)
			token := fmt.Sprintf("tokld%d", i)
			rs := newRelayStub(t, token)
			t.Cleanup(func() { closeVmConsoleByToken(token); time.Sleep(200 * time.Millisecond) })
			d := &CommandDispatcher{serverURL: "http://" + rs.ln.Addr().String(), apiKey: "k"}
			go func() {
				_, _ = d.handleOpenVmConsole(AgentCommand{ID: "c1", Type: "open_vm_console", Payload: map[string]interface{}{
					"sessionToken": token, "vmId": "0B6A3C2E-1111-2222-3333-444455556666", "installPolicy": "manual",
				}})
			}()
			var ws *wsConn
			select {
			case ws = <-rs.conns:
			case <-time.After(10 * time.Second):
				t.Fatal("the agent never dialled the relay")
			}
			var gotErr map[string]interface{}
			deadline := time.Now().Add(15 * time.Second)
			for gotErr == nil && time.Now().Before(deadline) {
				_ = ws.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				op, p, err := ws.ReadFrame()
				if err != nil {
					break
				}
				if op == 0x1 {
					var m map[string]interface{}
					_ = json.Unmarshal(p, &m)
					if m["type"] == "error" {
						gotErr = m
					}
				}
			}
			if gotErr == nil || gotErr["code"] != c.want || gotErr["retry"] != false {
				t.Fatalf("exit %s nt6=%v: want %s, got %v", c.exit, c.nt6, c.want, gotErr)
			}
		})
	}
}

func TestVmConsoleRefusals(t *testing.T) {
	withTestHost(t)
	savedState := vmcStateOf
	t.Cleanup(func() { vmcStateOf = savedState })
	token := "tok-off"
	rs := newRelayStub(t, token)
	d := &CommandDispatcher{serverURL: "http://" + rs.ln.Addr().String(), apiKey: "k"}
	vmID := "0B6A3C2E-1111-2222-3333-444455556666"

	read := func(ws *wsConn) map[string]interface{} {
		for {
			_ = ws.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			op, p, err := ws.ReadFrame()
			if err != nil {
				return nil
			}
			if op == 0x1 {
				var m map[string]interface{}
				_ = json.Unmarshal(p, &m)
				if m["type"] == "error" {
					return m
				}
			}
		}
	}

	// VM turned off.
	vmcStateOf = func(string) (string, error) { return "Off", nil }
	errCh := make(chan error, 1)
	go func() {
		_, err := d.handleOpenVmConsole(AgentCommand{ID: "c", Payload: map[string]interface{}{"sessionToken": token, "vmId": vmID}})
		errCh <- err
	}()
	ws := <-rs.conns
	if m := read(ws); m == nil || m["code"] != vmErrOff {
		t.Fatalf("vm off: %v", m)
	}
	if err := <-errCh; err == nil || !strings.HasPrefix(err.Error(), "vm_off: ") {
		t.Fatalf("ack error must carry the code: %v", err)
	}

	// Helper missing + policy frozen: refused, nothing downloaded.
	vmcStateOf = func(string) (string, error) { return "Running", nil }
	go func() {
		_, err := d.handleOpenVmConsole(AgentCommand{ID: "c", Payload: map[string]interface{}{"sessionToken": token, "vmId": vmID, "installPolicy": "frozen"}})
		errCh <- err
	}()
	ws = <-rs.conns
	if m := read(ws); m == nil || m["code"] != vmErrDisabled {
		t.Fatalf("frozen: %v", m)
	}
	if err := <-errCh; err == nil || !strings.HasPrefix(err.Error(), "vmconsole_disabled: ") {
		t.Fatalf("frozen ack: %v", err)
	}

	// Bad vmId: refused before anything (no relay dial).
	if _, err := d.handleOpenVmConsole(AgentCommand{ID: "c", Payload: map[string]interface{}{"sessionToken": token, "vmId": "x; rm -rf"}}); err == nil {
		t.Fatal("invalid vmId accepted")
	}
}

// Optional: the REAL helper build against a closed local port 2179 (no
// Hyper-V needed): set VMC_REAL_HELPER_DIR to an unpacked bundle folder.
func TestVmConsoleRealHelperSmoke(t *testing.T) {
	src := os.Getenv("VMC_REAL_HELPER_DIR")
	if src == "" {
		t.Skip("VMC_REAL_HELPER_DIR not set")
	}
	withTestHost(t)
	savedState := vmcStateOf
	vmcStateOf = func(string) (string, error) { return "Running", nil }
	t.Cleanup(func() { vmcStateOf = savedState })
	base := vmConsoleDir()
	sha := strings.Repeat("cd", 32)
	cur, _ := json.Marshal(vmcCurrent{SHA256: sha, Dir: "b-" + sha[:12], Protocol: 2})
	_ = os.MkdirAll(base, 0o755)
	// A junction would do; a copy keeps the test simple.
	dst := filepath.Join(base, "b-"+sha[:12])
	if out, err := exec.Command("robocopy", src, dst, "/E", "/NJH", "/NJS", "/NFL", "/NDL").CombinedOutput(); err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() >= 8 {
			t.Fatalf("copy bundle: %v %s", err, out)
		}
	}
	_ = os.WriteFile(filepath.Join(base, "current.json"), cur, 0o644)
	token := "tok-real"
	rs := newRelayStub(t, token)
	t.Cleanup(func() { closeVmConsoleByToken(token); time.Sleep(500 * time.Millisecond) })
	d := &CommandDispatcher{serverURL: "http://" + rs.ln.Addr().String(), apiKey: "k"}
	go func() {
		_, _ = d.handleOpenVmConsole(AgentCommand{ID: "c", Payload: map[string]interface{}{
			"sessionToken": token, "vmId": "00000000-0000-0000-0000-000000000000",
		}})
	}()
	ws := <-rs.conns
	var states []string
	for {
		_ = ws.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		op, p, err := ws.ReadFrame()
		if err != nil {
			t.Fatalf("no error message before the close (states %v): %v", states, err)
		}
		if op != 0x1 {
			continue
		}
		var m map[string]interface{}
		_ = json.Unmarshal(p, &m)
		if m["type"] == "vm_state" {
			states = append(states, m["state"].(string))
		}
		if m["type"] == "error" {
			if m["code"] != vmErrConnectFailed {
				t.Fatalf("real helper: %v (states %v)", m, states)
			}
			t.Logf("real helper: states %v, error %v", states, m["message"])
			return
		}
	}
}
