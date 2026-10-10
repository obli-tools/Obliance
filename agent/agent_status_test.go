package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// useTempConfigDir points configDir / configFile / statusFile at a temp dir
// for the duration of the test.
func useTempConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldDir, oldCfg, oldStatus := configDir, configFile, statusFile
	configDir = dir
	configFile = filepath.Join(dir, "config.json")
	statusFile = filepath.Join(dir, "status.json")
	t.Cleanup(func() { configDir, configFile, statusFile = oldDir, oldCfg, oldStatus })
	return dir
}

func TestWriteAgentStatusHasNoSecret(t *testing.T) {
	useTempConfigDir(t)
	if err := writeAgentStatus("4.5.99"); err != nil {
		t.Fatalf("writeAgentStatus: %v", err)
	}
	data, err := os.ReadFile(statusFile)
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("status.json is not JSON: %v", err)
	}
	if len(m) != 1 || m["agentVersion"] != "4.5.99" {
		t.Fatalf("status.json must only carry agentVersion, got %s", data)
	}
	// Rewritten (not appended) on the next start.
	if err := writeAgentStatus("4.6.0"); err != nil {
		t.Fatalf("writeAgentStatus #2: %v", err)
	}
	data, _ = os.ReadFile(statusFile)
	if !strings.Contains(string(data), `"4.6.0"`) || strings.Contains(string(data), "4.5.99") {
		t.Fatalf("status.json not replaced: %s", data)
	}
	assertNoTempLeft(t, configDir)
}

func TestSaveConfigRoundTrip(t *testing.T) {
	useTempConfigDir(t)
	in := &Config{ServerURL: "https://obliance.example", APIKey: "k-secret", DeviceUUID: "u", CheckIntervalSeconds: 60, AgentVersion: "1.2.3"}
	if err := saveConfig(in); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	assertNoTempLeft(t, configDir)
	if !canReplaceSecretFiles() {
		// Windows, non-elevated test run: the protected DACL (SYSTEM +
		// Administrators) correctly locks the test user out.
		t.Skip("reading / replacing config.json needs an elevated token, as intended")
	}
	in.APIKey = "k-rotated"
	if err := saveConfig(in); err != nil { // replace an existing file
		t.Fatalf("saveConfig #2: %v", err)
	}
	out, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if out.APIKey != "k-rotated" || out.ServerURL != in.ServerURL {
		t.Fatalf("round trip mismatch: %+v", out)
	}
	assertNoTempLeft(t, configDir)
}

func assertNoTempLeft(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}
