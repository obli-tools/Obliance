package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ── Running scripts registry (for cancel support) ────────────────────────────

var (
	runningScripts   = make(map[string]context.CancelFunc) // cmdID -> cancel
	runningScriptsMu sync.Mutex
)

func registerRunningScript(cmdID string, cancel context.CancelFunc) {
	runningScriptsMu.Lock()
	runningScripts[cmdID] = cancel
	runningScriptsMu.Unlock()
}

func unregisterRunningScript(cmdID string) {
	runningScriptsMu.Lock()
	delete(runningScripts, cmdID)
	runningScriptsMu.Unlock()
}

// CancelRunningScript cancels a running script by its command ID.
func CancelRunningScript(cmdID string) bool {
	runningScriptsMu.Lock()
	cancel, ok := runningScripts[cmdID]
	runningScriptsMu.Unlock()
	if ok {
		cancel()
		return true
	}
	return false
}

// ── Script types ───────────────────────────────────────────────────────────────

// ScriptCommand describes a script to be executed by the agent.
type ScriptCommand struct {
	ID             string         `json:"id"`
	Runtime        string         `json:"runtime"` // powershell, pwsh, cmd, bash, zsh, sh, python, python3, perl, ruby
	Content        string         `json:"content"`
	Parameters     map[string]any `json:"parameters"`
	TimeoutSeconds int            `json:"timeoutSeconds"`
	RunAs          string         `json:"runAs"` // system or user
	// SecretNames: parameters whose value is secret (payload
	// secretParameterNames) — never substituted into the script text nor
	// passed positionally. ParamOrder: definition order (parameterOrder).
	// See script_params.go.
	SecretNames []string `json:"secretParameterNames"`
	ParamOrder  []string `json:"parameterOrder"`
}

// ScriptResult holds the output from an executed script.
type ScriptResult struct {
	ExitCode int    `json:"exitCode"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Duration int    `json:"duration"` // milliseconds
}

// ── Execution ─────────────────────────────────────────────────────────────────

// ExecuteScript runs the script described by cmd and returns the result.
// It creates a temporary file, applies parameter substitution, chooses the
// correct interpreter, enforces a timeout, and cleans up on completion.
func ExecuteScript(cmd ScriptCommand) (*ScriptResult, error) {
	if cmd.Content == "" {
		return nil, fmt.Errorf("script content is empty")
	}

	// Apply {{PARAM_name}} substitutions (non-secret values only; a secret
	// placeholder becomes a reference to its env var — script_params.go).
	content := applyParameters(cmd.Content, cmd.Runtime, cmd.Parameters, cmd.SecretNames)

	// PowerShell with parameter values: run through the splat wrapper
	// (script_params.go), which then carries the TLS preamble below.
	isPS := strings.EqualFold(cmd.Runtime, "powershell") || strings.EqualFold(cmd.Runtime, "pwsh")
	useWrapper := isPS && len(cmd.Parameters) > 0

	// Windows < 10 with PowerShell < 5: enable TLS 1.2 for the script's .NET
	// web calls (pscompat.go, withPSTLS12Preamble — safe, documented).
	tlsPreamble := ""
	if runtime.GOOS == "windows" && strings.EqualFold(cmd.Runtime, "powershell") && osNeedsNT6Build() {
		if useWrapper {
			if m := psMajorVersion(); m > 0 && m < 5 {
				tlsPreamble = psTLS12Preamble
			}
		} else {
			content = withPSTLS12Preamble(content, psMajorVersion())
		}
	}

	// Write the script to a temp file with the appropriate extension.
	ext := scriptExtension(cmd.Runtime)
	tmpFile, err := os.CreateTemp("", "obliscript-*"+ext)
	if err != nil {
		return nil, fmt.Errorf("create temp script file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("write script content: %w", err)
	}
	tmpFile.Close()

	// On Unix the file must be executable for sh/bash/zsh.
	if runtime.GOOS != "windows" {
		_ = os.Chmod(tmpPath, 0700)
	}

	// Build the command arguments (PowerShell with values: the wrapper runs
	// the script; shells: non-secret values also as positional arguments).
	runPath := tmpPath
	if useWrapper {
		wrapperPath, werr := writePSParamWrapper(tmpPath, tlsPreamble)
		if werr != nil {
			return nil, werr
		}
		defer os.Remove(wrapperPath)
		runPath = wrapperPath
	}
	execArgs, err := buildExecArgs(cmd.Runtime, runPath)
	if err != nil {
		return nil, err
	}
	execArgs = append(execArgs, scriptPositionalArgs(cmd.Runtime, cmd.Parameters, cmd.SecretNames, cmd.ParamOrder)...)

	// Determine timeout.
	timeout := cmd.TimeoutSeconds
	if timeout <= 0 {
		timeout = 300 // 5 minutes default
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	// Register so this script can be cancelled remotely
	if cmd.ID != "" {
		registerRunningScript(cmd.ID, cancel)
		defer unregisterRunningScript(cmd.ID)
	}

	execCmd := newCmdContext(ctx, execArgs[0], execArgs[1:]...)
	// OBLI_PARAM_<NAME> for this script process only (nil = inherit as is).
	if env := scriptParamEnv(cmd.Parameters, os.Environ()); env != nil {
		execCmd.Env = env
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	execCmd.Stdout = &stdoutBuf
	execCmd.Stderr = &stderrBuf

	start := time.Now()
	runErr := execCmd.Run()
	duration := int(time.Since(start).Milliseconds())

	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			exitCode = -1
			return &ScriptResult{
				ExitCode: exitCode,
				Stdout:   stdoutBuf.String(),
				Stderr:   fmt.Sprintf("script timed out after %d seconds", timeout),
				Duration: duration,
			}, nil
		} else if ctx.Err() == context.Canceled {
			exitCode = -2
			return &ScriptResult{
				ExitCode: exitCode,
				Stdout:   stdoutBuf.String(),
				Stderr:   "script cancelled by user",
				Duration: duration,
			}, nil
		} else {
			return nil, fmt.Errorf("exec script: %w", runErr)
		}
	}

	return &ScriptResult{
		ExitCode: exitCode,
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
		Duration: duration,
	}, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// scriptExtension returns the file extension appropriate for the runtime.
func scriptExtension(rt string) string {
	switch strings.ToLower(rt) {
	case "powershell", "pwsh":
		return ".ps1"
	case "cmd":
		return ".bat"
	case "python", "python3":
		return ".py"
	case "perl":
		return ".pl"
	case "ruby":
		return ".rb"
	default:
		return ".sh"
	}
}

// buildExecArgs constructs the interpreter command slice for the given runtime.
func buildExecArgs(rt, scriptPath string) ([]string, error) {
	switch strings.ToLower(rt) {
	case "powershell":
		return []string{
			"powershell.exe",
			"-NoProfile", "-NonInteractive",
			"-ExecutionPolicy", "Bypass",
			"-File", scriptPath,
		}, nil

	case "pwsh":
		return []string{
			"pwsh",
			"-NonInteractive",
			"-ExecutionPolicy", "Bypass",
			"-File", scriptPath,
		}, nil

	case "cmd":
		return []string{"cmd.exe", "/c", scriptPath}, nil

	case "bash":
		return []string{envInterpreter("bash"), scriptPath}, nil

	case "zsh":
		return []string{envInterpreter("zsh"), scriptPath}, nil

	case "sh":
		return []string{envInterpreter("sh"), scriptPath}, nil

	case "python":
		return []string{"python", scriptPath}, nil

	case "python3":
		return []string{"python3", scriptPath}, nil

	case "perl":
		return []string{"perl", scriptPath}, nil

	case "ruby":
		return []string{"ruby", scriptPath}, nil

	default:
		// Unknown runtime: attempt to run the file directly (Unix) or via cmd (Windows).
		if runtime.GOOS == "windows" {
			return []string{"cmd.exe", "/c", scriptPath}, nil
		}
		return []string{envInterpreter("sh"), scriptPath}, nil
	}
}

// envInterpreter returns "/usr/bin/env <interp>" as a two-element slice would,
// but since exec.Command requires a single executable, we use the env trick:
// pass "/usr/bin/env" as the program and the interpreter name as the first arg.
// This function returns the fully-qualified path-or-env path for a shell.
func envInterpreter(shell string) string {
	// Prefer the known absolute path so we don't depend on PATH being set.
	for _, path := range []string{
		filepath.Join("/usr/bin", shell),
		filepath.Join("/bin", shell),
		filepath.Join("/usr/local/bin", shell),
	} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	// Fall back to bare name and let the OS resolve via PATH.
	return shell
}
