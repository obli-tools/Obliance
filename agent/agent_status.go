package main

import (
	"encoding/json"
	"os"
)

// status.json — the NON-secret, world-readable companion of config.json.
//
// config.json carries the tenant API key and the server URL, so it is
// readable by root / SYSTEM / Administrators only (writeSecretFile: 0600 on
// Unix, protected SYSTEM + Administrators DACL on Windows). The tray runs as
// the logged-in user and only needs the agent version: it reads this file
// first (cmd/tray readAgentVersion) and falls back to config.json for agents
// older than this change. Never put a secret in here.
type agentStatus struct {
	AgentVersion string `json:"agentVersion"`
}

// writeAgentStatus (re)writes status.json — once per agent start, through a
// temp file + rename so a file planted or chmod'ed by someone else is
// replaced by a fresh one owned by the agent.
func writeAgentStatus(version string) error {
	data, err := json.MarshalIndent(agentStatus{AgentVersion: version}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}
	return writePublicFile(statusFile, data)
}
