package main

// VM interactive console (Hyper-V, "Layer B") — platform-independent parts,
// kept free of Win32 calls so they are unit-tested on every OS:
//
//   - the viewer → helper input filter (only console input reaches the
//     helper's stdin, one sanitised JSON line per message);
//   - the helper status ('S' frames, protocol 2) → viewer control messages;
//   - the error codes the agent reports (relay message + command ack);
//   - the install state reported in the push body (`vmConsole`);
//   - command progress reporting (install task lifecycle).
//
// The Windows bridge itself lives in vmconsole_windows.go; other OSes only
// get the stubs of vmconsole_other.go.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// vmConsoleHelperProtocol is the helper protocol this agent speaks (stdout
// 'S' status frames, type_text / sas / release_all / refresh input). A
// bundle without vmconsole-version.txt is protocol 1 (frames + mouse/key).
const vmConsoleHelperProtocol = 2

// vmConsoleMaxTypeText bounds one "type clipboard text" request (characters).
const vmConsoleMaxTypeText = 20000

// validVMGUID (hyperv_v1.go): a Hyper-V VM id is a bare GUID.

var klidRe = regexp.MustCompile(`^[0-9A-Fa-f]{8}$`)

// ── Error codes (relay `error` message + command ack "code: message") ───────

// Codes understood by the viewer (describeError) and by the server, which
// keeps the code when it fails the session from the command ack.
const (
	vmErrOff           = "vm_off"                    // VM turned off / saved
	vmErrNotFound      = "vm_not_found"              // no such VM on this host
	vmErrNotHyperV     = "vm_not_hyperv"             // host has no Hyper-V role
	vmErrDisabled      = "vmconsole_disabled"        // policy forbids installing the helper
	vmErrInstallFailed = "vmconsole_install_failed"  // helper download / install failed
	vmErrHelperStart   = "vm_console_start_failed"   // helper could not be started
	vmErrConnectFailed = "vm_console_connect_failed" // FreeRDP could not reach the VM console
	vmErrTaken         = "vm_console_taken"          // another console connection took over
	vmErrAuth          = "vm_console_auth"           // authentication refused
	vmErrClosed        = "vm_console_closed"         // the host closed the console
	vmErrLost          = "vm_console_lost"           // connection lost, reconnect gave up
	vmErrEncoder       = "vm_console_encoder"        // H.264 encoder failure
	vmErrEnded         = "vm_console_ended"          // helper exited without a reason
	vmErrPrivacy       = "privacy_mode"              // privacy mode refused the console
	vmErrRelay         = "relay_refused"             // relay WebSocket could not be opened
	vmErrOSUnsupported = "vm_console_os_unsupported" // helper cannot load on this Windows (NT 6.x)
)

// vmCodedError is an error carrying a viewer code. Its Error() text is
// "code: message" — the server extracts the code from a failed ack.
type vmCodedError struct {
	Code    string
	Message string
}

func (e *vmCodedError) Error() string { return e.Code + ": " + e.Message }

func vmErr(code, format string, a ...interface{}) *vmCodedError {
	return &vmCodedError{Code: code, Message: fmt.Sprintf(format, a...)}
}

// vmRelayError is the relay control message for a coded error.
func vmRelayError(e *vmCodedError) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"type": "error", "code": e.Code, "agentCode": e.Code, "message": e.Message, "retry": false,
	})
	return b
}

// ── Viewer → helper input filter ─────────────────────────────────────────────

// vmConsoleInput is the subset of the viewer's messages the helper reads.
type vmConsoleInput struct {
	Type   string   `json:"type"`
	Action string   `json:"action,omitempty"`
	X      *float64 `json:"x,omitempty"`
	Y      *float64 `json:"y,omitempty"`
	Button *float64 `json:"button,omitempty"`
	Delta  *float64 `json:"delta,omitempty"`
	Code   string   `json:"code,omitempty"`
	Key    string   `json:"key,omitempty"`
	Text   *string  `json:"text,omitempty"`
	Layout string   `json:"layout,omitempty"`
	Guest  string   `json:"guest,omitempty"`
}

var vmMouseActions = map[string]bool{"move": true, "down": true, "up": true, "scroll": true, "hscroll": true}

func clampInt(v float64, lo, hi int) int {
	if v != v { // NaN
		return lo
	}
	if v < float64(lo) {
		return lo
	}
	if v > float64(hi) {
		return hi
	}
	return int(v)
}

// filterVMConsoleInput turns one viewer WebSocket text message into the
// single JSON line the helper reads (no trailing newline), or ok=false when
// the message is not console input (clipboard, files, audio, presence…).
// `protocol` is the helper's protocol: a protocol-1 helper only gets mouse
// and key messages. Nothing the viewer sends reaches the helper unchecked.
func filterVMConsoleInput(raw []byte, protocol int) (line []byte, ok bool) {
	if len(raw) == 0 || len(raw) > 2<<20 {
		return nil, false
	}
	var in vmConsoleInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, false
	}
	out := map[string]interface{}{"type": in.Type}
	switch in.Type {
	case "mouse":
		if !vmMouseActions[in.Action] {
			return nil, false
		}
		if protocol < 2 && in.Action == "hscroll" {
			return nil, false
		}
		out["action"] = in.Action
		x, y := 0, 0
		if in.X != nil {
			x = clampInt(*in.X, 0, 65535)
		}
		if in.Y != nil {
			y = clampInt(*in.Y, 0, 65535)
		}
		out["x"], out["y"] = x, y
		if in.Action == "down" || in.Action == "up" {
			b := 0
			if in.Button != nil {
				b = clampInt(*in.Button, 0, 4)
			}
			out["button"] = b
		}
		if in.Action == "scroll" || in.Action == "hscroll" {
			d := 0
			if in.Delta != nil {
				d = clampInt(*in.Delta, -100, 100)
			}
			if d == 0 {
				return nil, false
			}
			out["delta"] = d
		}
	case "key":
		if in.Action != "down" && in.Action != "up" {
			return nil, false
		}
		if len(in.Code) > 40 {
			return nil, false
		}
		// `key` only matters for an unknown code (one typed character, see
		// inject_key in vmconsole.c). Named keys (Backspace, ArrowLeft,
		// ScrollLock…) are longer than that: drop the name, keep the code —
		// rejecting the whole message lost those keys.
		if utf8.RuneCountInString(in.Key) > 8 {
			in.Key = ""
		}
		if in.Code == "" && in.Key == "" {
			return nil, false
		}
		out["action"] = in.Action
		if in.Code != "" {
			out["code"] = in.Code
		}
		if in.Key != "" {
			out["key"] = in.Key
		}
	case "type_text":
		if protocol < 2 || in.Text == nil || *in.Text == "" {
			return nil, false
		}
		text := *in.Text
		if !utf8.ValidString(text) {
			text = strings.ToValidUTF8(text, "")
		}
		if utf8.RuneCountInString(text) > vmConsoleMaxTypeText {
			r := []rune(text)
			text = string(r[:vmConsoleMaxTypeText])
		}
		out["text"] = text
		if klidRe.MatchString(in.Layout) {
			out["layout"] = strings.ToUpper(in.Layout)
		}
		// Guest OS the helper types for ("windows" | "linux"; anything else
		// dropped = windows, the helper's default and an old Desktop's mode).
		if in.Guest == "windows" || in.Guest == "linux" {
			out["guest"] = in.Guest
		}
	case "type_cancel", "sas", "release_all", "refresh":
		if protocol < 2 {
			return nil, false
		}
	default:
		return nil, false
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, false
	}
	return b, true
}

// isDroppableInput: a mouse move may be dropped when the helper lags behind
// (the next one supersedes it); presses, releases, keys and text never are.
func isDroppableInput(line []byte) bool {
	return strings.HasPrefix(string(line), `{"action":"move"`)
}

// ── Helper status ('S' frame) → viewer ───────────────────────────────────────

// vmHelperStatus is the JSON payload of an 'S' frame (helper protocol 2).
type vmHelperStatus struct {
	State   string `json:"state"`
	Width   int    `json:"width,omitempty"`
	Height  int    `json:"height,omitempty"`
	Unicode bool   `json:"unicode,omitempty"`
	Attempt int    `json:"attempt,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	Done    int    `json:"done,omitempty"`
	Total   int    `json:"total,omitempty"`
}

// helperEndedCode maps the helper's `ended` code to the viewer code
// ("" = a normal end the viewer is not told about).
func helperEndedCode(code string) string {
	switch code {
	case "connect_failed":
		return vmErrConnectFailed
	case "other_connection":
		return vmErrTaken
	case "auth_failed":
		return vmErrAuth
	case "server_closed":
		return vmErrClosed
	case "reconnect_failed":
		return vmErrLost
	case "encoder_failed":
		return vmErrEncoder
	case "stdin_closed", "":
		return ""
	default:
		return vmErrEnded
	}
}

// mapHelperStatus converts an 'S' payload into the control message relayed
// to the viewer. terminal: the helper is ending (an `error` goes out).
func mapHelperStatus(payload []byte) (msg []byte, terminal bool, ok bool) {
	var st vmHelperStatus
	if err := json.Unmarshal(payload, &st); err != nil || st.State == "" {
		return nil, false, false
	}
	switch st.State {
	case "ended":
		code := helperEndedCode(st.Code)
		if code == "" {
			return nil, true, false
		}
		text := strings.TrimSpace(st.Message)
		if st.Error != "" {
			text = strings.TrimSpace(text + " (" + st.Error + ")")
		}
		return vmRelayError(&vmCodedError{Code: code, Message: truncateStr(text, 300)}), true, true
	case "connecting", "connected", "reconnecting", "typing", "typing_cancelled":
		m := map[string]interface{}{"type": "vm_state", "state": st.State}
		switch st.State {
		case "connected":
			m["width"], m["height"], m["unicode"] = st.Width, st.Height, st.Unicode
		case "reconnecting":
			m["attempt"], m["reason"] = st.Attempt, truncateStr(st.Reason, 60)
		case "typing", "typing_cancelled":
			m["done"], m["total"] = st.Done, st.Total
		}
		b, _ := json.Marshal(m)
		return b, false, true
	}
	return nil, false, false
}

// vmStateMessage builds a {"type":"vm_state",...} message (agent-side states:
// preparing, installing, starting).
func vmStateMessage(state string, extra map[string]interface{}) []byte {
	m := map[string]interface{}{"type": "vm_state", "state": state}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

// vmInitMessage is the viewer `init` for a helper frame size. Features tell
// the viewer what this console understands (vm_* only: no clipboard sync,
// files, audio or monitors on a VM console).
func vmInitMessage(w, h uint32, protocol int) []byte {
	feats := []string{"vm_console"}
	if protocol >= 2 {
		feats = append(feats, "vm_type_text", "vm_sas", "vm_release_all", "vm_status")
	}
	b, _ := json.Marshal(map[string]interface{}{
		"type": "init", "width": w, "height": h, "fps": 30, "codec": "h264", "features": feats,
	})
	return b
}

// parseHelperVersion reads vmconsole-version.txt ("protocol=2\nbuilt=...").
func parseHelperVersion(text string) (protocol int, built string) {
	protocol = 1
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "protocol=") {
			var p int
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, "protocol="), "%d", &p); err == nil && p > 0 {
				protocol = p
			}
		} else if strings.HasPrefix(line, "built=") {
			built = truncateStr(strings.TrimPrefix(line, "built="), 40)
		}
	}
	return protocol, built
}

// ── Install state (push body `vmConsole`) ────────────────────────────────────

// VmConsoleReport is the helper bundle state of a Hyper-V host.
type VmConsoleReport struct {
	// not_installed | installing | installed | error
	State       string `json:"state"`
	SHA256      string `json:"sha256,omitempty"`
	InstalledAt string `json:"installedAt,omitempty"`
	Protocol    int    `json:"protocol,omitempty"`
	Built       string `json:"built,omitempty"`
	Signed      *bool  `json:"signed,omitempty"`
	Error       string `json:"error,omitempty"`
	Phase       string `json:"phase,omitempty"`
	Percent     int    `json:"percent,omitempty"`
	UpdatedAt   string `json:"updatedAt,omitempty"`
}

var (
	vmcStateMu sync.Mutex
	vmcState   *VmConsoleReport
)

func setVMConsoleState(r VmConsoleReport) {
	r.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	vmcStateMu.Lock()
	vmcState = &r
	vmcStateMu.Unlock()
}

// ── Command progress (task lifecycle) ────────────────────────────────────────

// reportCommandProgress tells the server a long command is running and how
// far it is (Tasks: "Running — downloading 42 %"). Over the command channel
// when it is up (instant), otherwise as an ack_running for the next push.
func (d *CommandDispatcher) reportCommandProgress(cmdID, cmdType string, progress map[string]interface{}) {
	if cmdID == "" {
		return
	}
	if sendOnCommandChannelErr(map[string]interface{}{
		"type": "progress", "id": cmdID, "commandType": cmdType, "result": map[string]interface{}{"progress": progress},
	}) == nil {
		return
	}
	d.addAck(CommandAck{CommandID: cmdID, CommandType: cmdType, Status: "ack_running",
		Result: map[string]interface{}{"progress": progress}})
}

// finishCommand reports the final outcome of a command that is not answered
// through its own dispatch path (the on-demand install started by an
// open_vm_console). Command channel first, push ack otherwise.
func (d *CommandDispatcher) finishCommand(cmdID, cmdType string, result interface{}, err error) {
	if cmdID == "" {
		return
	}
	ack := hubAck{Type: "ack", ID: cmdID, CommandType: cmdType, Success: err == nil}
	if err != nil {
		ack.Error = err.Error()
	} else if result != nil {
		if b, e := json.Marshal(result); e == nil {
			ack.Result = b
		}
	}
	if sendOnCommandChannelErr(ack) == nil {
		return
	}
	ca := CommandAck{CommandID: cmdID, CommandType: cmdType, Status: "success", Result: result}
	if err != nil {
		ca.Status = "failure"
		ca.Result = map[string]string{"error": err.Error()}
	}
	d.addAck(ca)
	TriggerImmediatePush()
}

// progressThrottle lets a progress report through every `step` percent or
// every `every`, and always for a phase change.
type progressThrottle struct {
	step    int
	every   time.Duration
	phase   string
	percent int
	at      time.Time
}

func (p *progressThrottle) allow(phase string, percent int, now time.Time) bool {
	if phase != p.phase || percent >= p.percent+p.step || now.Sub(p.at) >= p.every || (percent == 100 && p.percent != 100) {
		p.phase, p.percent, p.at = phase, percent, now
		return true
	}
	return false
}
