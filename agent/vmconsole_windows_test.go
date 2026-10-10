//go:build windows

package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func makeBundle(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type bundleServer struct {
	srv      *httptest.Server
	hits     atomic.Int32
	body     []byte
	shaHdr   string
	status   int
	slowOnce chan struct{}
}

func newBundleServer(t *testing.T, body []byte) *bundleServer {
	b := &bundleServer{body: body, status: 200}
	sum := sha256.Sum256(body)
	b.shaHdr = hex.EncodeToString(sum[:])
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		if r.URL.Path != "/api/agent/download/vmconsole.zip" || r.Header.Get("X-Api-Key") != "k" {
			w.WriteHeader(404)
			return
		}
		if b.slowOnce != nil {
			<-b.slowOnce
		}
		if b.status != 200 {
			w.WriteHeader(b.status)
			return
		}
		if b.shaHdr != "" {
			w.Header().Set("X-Content-SHA256", b.shaHdr)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(b.body)))
		_, _ = w.Write(b.body)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func withTestHost(t *testing.T) {
	t.Helper()
	savedDir, savedHost := configDir, vmcIsHyperVHost
	configDir = t.TempDir()
	vmcIsHyperVHost = func() bool { return true }
	vmcStateMu.Lock()
	vmcState = nil
	vmcStateMu.Unlock()
	t.Cleanup(func() { configDir, vmcIsHyperVHost = savedDir, savedHost })
}

func TestVmcInstallLifecycle(t *testing.T) {
	withTestHost(t)
	body := makeBundle(t, map[string]string{
		"vmconsole.exe": "MZ fake helper", "libfreerdp3.dll": "dll", "vmconsole-version.txt": "protocol=2\nbuilt=2026-10-02\n",
	})
	bs := newBundleServer(t, body)
	d := &CommandDispatcher{serverURL: bs.srv.URL, apiKey: "k"}

	if _, _, ok := vmcInstalled(); ok {
		t.Fatal("nothing installed yet")
	}
	if r := vmConsoleReportForPush(); r == nil || r.State != "not_installed" {
		t.Fatalf("report before install: %+v", r)
	}

	var mu sync.Mutex
	var phases []string
	res, err := d.handleInstallVmConsole(AgentCommand{ID: "cmd-1", Type: "install_vm_console", Payload: map[string]interface{}{}})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	m := res.(map[string]interface{})
	if m["status"] != "installed" || m["sha256"] != bs.shaHdr || m["protocol"] != 2 {
		t.Fatalf("result: %+v", m)
	}
	// Progress went out as ack_running acks (no command channel in tests).
	for _, a := range d.GetAndClearAcks() {
		if a.CommandID != "cmd-1" || a.Status != "ack_running" {
			t.Fatalf("unexpected ack %+v", a)
		}
		p := a.Result.(map[string]interface{})["progress"].(map[string]interface{})
		mu.Lock()
		phases = append(phases, p["phase"].(string))
		mu.Unlock()
	}
	joined := strings.Join(phases, ",")
	for _, want := range []string{"start", "download", "verify", "extract", "done"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("phase %q never reported: %s", want, joined)
		}
	}
	dir, cur, ok := vmcInstalled()
	if !ok || cur.SHA256 != bs.shaHdr || !strings.HasPrefix(filepath.Base(dir), "b-"+bs.shaHdr[:12]) || cur.Protocol != 2 {
		t.Fatalf("installed: dir=%s cur=%+v ok=%v", dir, cur, ok)
	}
	if r := vmConsoleReportForPush(); r == nil || r.State != "installed" || r.SHA256 != bs.shaHdr {
		t.Fatalf("report after install: %+v", r)
	}
	// Already installed: no new download.
	hits := bs.hits.Load()
	res, err = d.handleInstallVmConsole(AgentCommand{ID: "cmd-2", Type: "install_vm_console", Payload: map[string]interface{}{}})
	if err != nil || res.(map[string]interface{})["status"] != "already_installed" || bs.hits.Load() != hits {
		t.Fatalf("second install: %+v %v (hits %d→%d)", res, err, hits, bs.hits.Load())
	}
	// Repair (force): downloaded again into a new folder, the old one cleaned.
	res, err = d.handleInstallVmConsole(AgentCommand{ID: "cmd-3", Type: "install_vm_console", Payload: map[string]interface{}{"force": true}})
	if err != nil || res.(map[string]interface{})["status"] != "installed" {
		t.Fatalf("repair: %+v %v", res, err)
	}
	dir2, _, _ := vmcInstalled()
	if dir2 == dir {
		t.Fatal("repair must unpack into a new folder (the old one may be in use)")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("old bundle folder not cleaned: %v", err)
	}
}

func TestVmcInstallFailures(t *testing.T) {
	withTestHost(t)
	body := makeBundle(t, map[string]string{"vmconsole.exe": "MZ"})
	bs := newBundleServer(t, body)
	d := &CommandDispatcher{serverURL: bs.srv.URL, apiKey: "k"}

	// Integrity: a hash that does not match → refused, nothing installed.
	bs.shaHdr = strings.Repeat("0", 64)
	_, err := d.handleInstallVmConsole(AgentCommand{ID: "x", Type: "install_vm_console"})
	if err == nil || !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("sha mismatch: %v", err)
	}
	if _, _, ok := vmcInstalled(); ok {
		t.Fatal("installed despite a bad hash")
	}
	if r := vmConsoleReportForPush(); r == nil || r.State != "error" || !strings.Contains(r.Error, "integrity") {
		t.Fatalf("report after failure: %+v", r)
	}
	// No hash at all → refused.
	bs.shaHdr = ""
	if _, err := d.handleInstallVmConsole(AgentCommand{ID: "x", Type: "install_vm_console"}); err == nil || !strings.Contains(err.Error(), "integrity hash") {
		t.Fatalf("no hash: %v", err)
	}
	// Server without a bundle.
	bs.status = 404
	if _, err := d.handleInstallVmConsole(AgentCommand{ID: "x", Type: "install_vm_console"}); err == nil || !strings.Contains(err.Error(), "no console bundle") {
		t.Fatalf("404: %v", err)
	}
	// A zip without the helper.
	bs.status = 200
	other := makeBundle(t, map[string]string{"readme.txt": "x"})
	bs.body = other
	sum := sha256.Sum256(other)
	bs.shaHdr = hex.EncodeToString(sum[:])
	if _, err := d.handleInstallVmConsole(AgentCommand{ID: "x", Type: "install_vm_console"}); err == nil || !strings.Contains(err.Error(), "vmconsole.exe missing") {
		t.Fatalf("no helper in zip: %v", err)
	}
	// Never on a host without Hyper-V.
	vmcIsHyperVHost = func() bool { return false }
	if _, err := d.handleInstallVmConsole(AgentCommand{ID: "x", Type: "install_vm_console"}); err == nil || !strings.Contains(err.Error(), "not a Hyper-V host") {
		t.Fatalf("non Hyper-V host: %v", err)
	}
	if vmConsoleReportForPush() != nil {
		t.Fatal("a non Hyper-V host reports no vmConsole state")
	}
}

func TestVmcInstallSingleFlight(t *testing.T) {
	withTestHost(t)
	body := makeBundle(t, map[string]string{"vmconsole.exe": "MZ"})
	bs := newBundleServer(t, body)
	bs.slowOnce = make(chan struct{})
	d := &CommandDispatcher{serverURL: bs.srv.URL, apiKey: "k"}
	var wg sync.WaitGroup
	errs := make([]error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, _, errs[i] = d.vmcEnsure(false, nil)
		}(i)
	}
	time.Sleep(300 * time.Millisecond)
	close(bs.slowOnce)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if n := bs.hits.Load(); n != 1 {
		t.Fatalf("%d downloads for 3 concurrent callers (want 1)", n)
	}
}

func TestVmcLegacyFlatLayout(t *testing.T) {
	withTestHost(t)
	base := vmConsoleDir()
	_ = os.MkdirAll(base, 0o755)
	_ = os.WriteFile(filepath.Join(base, "vmconsole.exe"), []byte("MZ"), 0o644)
	dir, cur, ok := vmcInstalled()
	if !ok || dir != base || cur.SHA256 != "" || cur.Protocol != 1 {
		t.Fatalf("legacy layout: %s %+v %v", dir, cur, ok)
	}
	// A broken current.json pointing outside never wins.
	_ = os.WriteFile(filepath.Join(base, "current.json"), []byte(`{"dir":"..\\..\\Windows","sha256":"x"}`), 0o644)
	if dir, _, _ := vmcInstalled(); dir != base {
		t.Fatalf("current.json escaped the folder: %s", dir)
	}
}

func TestVmcUnzipBounds(t *testing.T) {
	dir := t.TempDir()
	// Paths in the archive are flattened: nothing lands outside dir.
	z := filepath.Join(dir, "a.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("../../evil.exe")
	_, _ = w.Write([]byte("x"))
	_ = zw.Close()
	_ = os.WriteFile(z, buf.Bytes(), 0o644)
	out := filepath.Join(dir, "out")
	if err := vmcUnzip(z, out, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "evil.exe")); err != nil {
		t.Fatal("flattened file missing")
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "evil.exe")); err == nil {
		t.Fatal("zip slip")
	}
}
