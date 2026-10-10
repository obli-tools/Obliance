package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func decode(t *testing.T, b []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("invalid JSON %q: %v", b, err)
	}
	return m
}

func TestFilterVMConsoleInputMouse(t *testing.T) {
	line, ok := filterVMConsoleInput([]byte(`{"type":"mouse","action":"move","x":12.7,"y":-4,"gen":3,"extra":"x"}`), 2)
	if !ok {
		t.Fatal("move refused")
	}
	m := decode(t, line)
	if m["x"].(float64) != 12 || m["y"].(float64) != 0 || m["gen"] != nil || m["extra"] != nil {
		t.Fatalf("move not sanitised: %s", line)
	}
	if !isDroppableInput(line) {
		t.Fatal("a move must be droppable")
	}
	line, ok = filterVMConsoleInput([]byte(`{"type":"mouse","action":"down","button":2,"x":5,"y":6}`), 2)
	if !ok || decode(t, line)["button"].(float64) != 2 || isDroppableInput(line) {
		t.Fatalf("press: %s ok=%v", line, ok)
	}
	if _, ok := filterVMConsoleInput([]byte(`{"type":"mouse","action":"down","button":9}`), 2); !ok {
		t.Fatal("button clamped, not refused")
	}
	if l, _ := filterVMConsoleInput([]byte(`{"type":"mouse","action":"down","button":9}`), 2); decode(t, l)["button"].(float64) != 4 {
		t.Fatal("button not clamped to 4")
	}
	line, ok = filterVMConsoleInput([]byte(`{"type":"mouse","action":"scroll","delta":-1,"x":1,"y":1}`), 2)
	if !ok || decode(t, line)["delta"].(float64) != -1 {
		t.Fatalf("scroll: %s", line)
	}
	if _, ok := filterVMConsoleInput([]byte(`{"type":"mouse","action":"scroll","delta":0}`), 2); ok {
		t.Fatal("a zero scroll is noise")
	}
	if _, ok := filterVMConsoleInput([]byte(`{"type":"mouse","action":"hscroll","delta":1}`), 1); ok {
		t.Fatal("hscroll needs protocol 2")
	}
	if _, ok := filterVMConsoleInput([]byte(`{"type":"mouse","action":"teleport"}`), 2); ok {
		t.Fatal("unknown mouse action accepted")
	}
}

func TestFilterVMConsoleInputKeysAndText(t *testing.T) {
	line, ok := filterVMConsoleInput([]byte(`{"type":"key","action":"down","code":"IntlBackslash","key":"<","ctrl":false}`), 1)
	if !ok {
		t.Fatal("key refused")
	}
	m := decode(t, line)
	if m["code"] != "IntlBackslash" || m["key"] != "<" || m["ctrl"] != nil {
		t.Fatalf("key: %s", line)
	}
	// Named keys longer than 8 characters (Backspace, arrows, ScrollLock…)
	// keep their code: they were dropped whole before.
	for _, k := range []string{"Backspace", "ArrowLeft", "ArrowRight", "ArrowDown", "ScrollLock", "PrintScreen", "ContextMenu"} {
		line, ok := filterVMConsoleInput([]byte(`{"type":"key","action":"down","code":"`+k+`","key":"`+k+`"}`), 1)
		if !ok {
			t.Fatalf("%s refused", k)
		}
		if m := decode(t, line); m["code"] != k || (len(k) > 8 && m["key"] != nil) {
			t.Fatalf("%s: %s", k, line)
		}
	}
	if _, ok := filterVMConsoleInput([]byte(`{"type":"key","action":"down","key":"Backspace"}`), 2); ok {
		t.Fatal("long key name without a code accepted")
	}
	if _, ok := filterVMConsoleInput([]byte(`{"type":"key","action":"down"}`), 2); ok {
		t.Fatal("key without code nor key accepted")
	}
	if _, ok := filterVMConsoleInput([]byte(`{"type":"key","action":"press","code":"KeyA"}`), 2); ok {
		t.Fatal("unknown key action accepted")
	}
	// type_text: protocol 2 only, newline inside stays escaped on ONE line.
	if _, ok := filterVMConsoleInput([]byte(`{"type":"type_text","text":"abc"}`), 1); ok {
		t.Fatal("type_text sent to a protocol-1 helper")
	}
	line, ok = filterVMConsoleInput([]byte(`{"type":"type_text","text":"ligne 1\nété €","layout":"0000040c"}`), 2)
	if !ok || strings.Contains(string(line), "\n") {
		t.Fatalf("type_text: %q ok=%v", line, ok)
	}
	m = decode(t, line)
	if m["text"] != "ligne 1\nété €" || m["layout"] != "0000040C" {
		t.Fatalf("type_text content: %s", line)
	}
	line, _ = filterVMConsoleInput([]byte(`{"type":"type_text","text":"x","layout":"../../etc"}`), 2)
	if decode(t, line)["layout"] != nil {
		t.Fatal("bogus layout passed through")
	}
	long := strings.Repeat("é", vmConsoleMaxTypeText+50)
	b, _ := json.Marshal(map[string]string{"type": "type_text", "text": long})
	line, ok = filterVMConsoleInput(b, 2)
	if !ok || len([]rune(decode(t, line)["text"].(string))) != vmConsoleMaxTypeText {
		t.Fatal("type_text not capped")
	}
	for _, typ := range []string{"sas", "release_all", "refresh", "type_cancel"} {
		if _, ok := filterVMConsoleInput([]byte(`{"type":"`+typ+`"}`), 2); !ok {
			t.Fatalf("%s refused", typ)
		}
		if _, ok := filterVMConsoleInput([]byte(`{"type":"`+typ+`"}`), 1); ok {
			t.Fatalf("%s sent to a protocol-1 helper", typ)
		}
	}
	// Everything else of the ObliReach protocol stays out of the helper.
	for _, other := range []string{
		`{"type":"clipboard_set","text":"secret"}`, `{"type":"file_upload_start"}`, `{"type":"audio_caps"}`,
		`{"type":"presence_state"}`, `not json`, ``,
	} {
		if _, ok := filterVMConsoleInput([]byte(other), 2); ok {
			t.Fatalf("%q reached the helper", other)
		}
	}
}

func TestFilterVMConsoleInputTypeTextGuest(t *testing.T) {
	// "windows" and "linux" pass through exactly.
	for _, g := range []string{"windows", "linux"} {
		line, ok := filterVMConsoleInput([]byte(`{"type":"type_text","text":"@","layout":"0000040C","guest":"`+g+`"}`), 2)
		if !ok {
			t.Fatalf("guest %s: refused", g)
		}
		if m := decode(t, line); m["guest"] != g || m["text"] != "@" || m["layout"] != "0000040C" {
			t.Fatalf("guest %s: %s", g, line)
		}
	}
	// Anything else is dropped (helper default = windows), the text still goes.
	for _, g := range []string{`"Linux"`, `"LINUX"`, `"macos"`, `""`, `" linux"`, `"linux\u0000"`, `"windows;rm"`, `1`, `true`, `null`, `["linux"]`, `{"a":1}`} {
		line, ok := filterVMConsoleInput([]byte(`{"type":"type_text","text":"x","guest":`+g+`}`), 2)
		if !ok {
			// a non-string guest makes the whole message invalid JSON for the
			// struct: refused, like any other ill-typed field.
			if strings.HasPrefix(g, `"`) {
				t.Fatalf("guest %s: string value refused the message", g)
			}
			continue
		}
		if m := decode(t, line); m["guest"] != nil || m["text"] != "x" {
			t.Fatalf("guest %s passed through: %s", g, line)
		}
	}
	// An old Desktop (no guest field): no guest in the helper line.
	line, ok := filterVMConsoleInput([]byte(`{"type":"type_text","text":"x"}`), 2)
	if !ok || decode(t, line)["guest"] != nil {
		t.Fatalf("no guest: %s ok=%v", line, ok)
	}
	// guest is a type_text field only.
	line, ok = filterVMConsoleInput([]byte(`{"type":"key","action":"down","code":"KeyA","guest":"linux"}`), 2)
	if !ok || decode(t, line)["guest"] != nil {
		t.Fatalf("guest on a key message: %s ok=%v", line, ok)
	}
	// Still protocol 2 only.
	if _, ok := filterVMConsoleInput([]byte(`{"type":"type_text","text":"x","guest":"linux"}`), 1); ok {
		t.Fatal("type_text with guest sent to a protocol-1 helper")
	}
}

func TestMapHelperStatus(t *testing.T) {
	msg, terminal, ok := mapHelperStatus([]byte(`{"state":"ended","code":"other_connection","message":"Another connection took the console","error":"0x0001000B"}`))
	if !ok || !terminal {
		t.Fatal("ended not relayed")
	}
	m := decode(t, msg)
	if m["type"] != "error" || m["code"] != vmErrTaken || m["retry"] != false || !strings.Contains(m["message"].(string), "0x0001000B") {
		t.Fatalf("ended: %s", msg)
	}
	for helper, viewer := range map[string]string{
		"connect_failed": vmErrConnectFailed, "auth_failed": vmErrAuth, "server_closed": vmErrClosed,
		"reconnect_failed": vmErrLost, "encoder_failed": vmErrEncoder, "weird": vmErrEnded,
	} {
		msg, _, _ := mapHelperStatus([]byte(`{"state":"ended","code":"` + helper + `"}`))
		if decode(t, msg)["code"] != viewer {
			t.Fatalf("%s -> %s", helper, msg)
		}
	}
	if _, terminal, ok := mapHelperStatus([]byte(`{"state":"ended","code":"stdin_closed"}`)); ok || !terminal {
		t.Fatal("stdin_closed is a normal end, not shown")
	}
	msg, terminal, ok = mapHelperStatus([]byte(`{"state":"reconnecting","attempt":3,"reason":"server_closed"}`))
	if !ok || terminal {
		t.Fatal("reconnecting")
	}
	m = decode(t, msg)
	if m["type"] != "vm_state" || m["state"] != "reconnecting" || m["attempt"].(float64) != 3 {
		t.Fatalf("reconnecting: %s", msg)
	}
	msg, _, _ = mapHelperStatus([]byte(`{"state":"connected","width":1024,"height":768,"unicode":true}`))
	m = decode(t, msg)
	if m["width"].(float64) != 1024 || m["unicode"] != true {
		t.Fatalf("connected: %s", msg)
	}
	msg, _, _ = mapHelperStatus([]byte(`{"state":"typing","done":200,"total":1000}`))
	if decode(t, msg)["done"].(float64) != 200 {
		t.Fatal("typing")
	}
	if _, _, ok := mapHelperStatus([]byte(`{"state":"bogus"}`)); ok {
		t.Fatal("unknown state relayed")
	}
	if _, _, ok := mapHelperStatus([]byte(`garbage`)); ok {
		t.Fatal("garbage relayed")
	}
}

func TestVMInitAndErrors(t *testing.T) {
	m := decode(t, vmInitMessage(1280, 800, 2))
	if m["type"] != "init" || m["width"].(float64) != 1280 || m["codec"] != "h264" {
		t.Fatalf("init: %v", m)
	}
	feats := m["features"].([]interface{})
	if len(feats) < 2 || feats[0] != "vm_console" {
		t.Fatalf("features: %v", feats)
	}
	if f := decode(t, vmInitMessage(800, 600, 1))["features"].([]interface{}); len(f) != 1 {
		t.Fatalf("protocol 1 features: %v", f)
	}
	e := vmErr(vmErrOff, "The VM is %s.", "off")
	if e.Error() != "vm_off: The VM is off." {
		t.Fatalf("coded error text: %q", e.Error())
	}
	r := decode(t, vmRelayError(e))
	if r["type"] != "error" || r["code"] != vmErrOff || r["retry"] != false {
		t.Fatalf("relay error: %v", r)
	}
}

func TestParseHelperVersion(t *testing.T) {
	p, b := parseHelperVersion("protocol=2\r\nbuilt=2026-10-02T10:00:00Z\r\n")
	if p != 2 || b != "2026-10-02T10:00:00Z" {
		t.Fatalf("got %d %q", p, b)
	}
	if p, _ := parseHelperVersion("garbage"); p != 1 {
		t.Fatal("default protocol must be 1")
	}
}

func TestProgressThrottle(t *testing.T) {
	th := &progressThrottle{step: 5, every: time.Hour}
	now := time.Now()
	if !th.allow("download", 0, now) {
		t.Fatal("first report")
	}
	if th.allow("download", 3, now) {
		t.Fatal("below step")
	}
	if !th.allow("download", 5, now) {
		t.Fatal("step reached")
	}
	if !th.allow("verify", 5, now) {
		t.Fatal("phase change")
	}
	if !th.allow("verify", 6, now.Add(2*time.Hour)) {
		t.Fatal("time elapsed")
	}
}

func TestHubAckFallbackAndRequeue(t *testing.T) {
	ca := hubAckToCommandAck(hubAck{ID: "a", CommandType: "install_vm_console", Success: false, Error: "boom"})
	if ca.Status != "failure" || ca.Result.(map[string]string)["error"] != "boom" {
		t.Fatalf("failure ack: %+v", ca)
	}
	ca = hubAckToCommandAck(hubAck{ID: "b", CommandType: "x", Success: true, Result: json.RawMessage(`{"status":"installed"}`)})
	if ca.Status != "success" || ca.Result.(map[string]interface{})["status"] != "installed" {
		t.Fatalf("success ack: %+v", ca)
	}
	d := &CommandDispatcher{}
	d.addAck(CommandAck{CommandID: "new"})
	d.requeueAcks([]CommandAck{{CommandID: "old1"}, {CommandID: "old2"}})
	got := d.GetAndClearAcks()
	if len(got) != 3 || got[0].CommandID != "old1" || got[2].CommandID != "new" {
		t.Fatalf("requeue order: %+v", got)
	}
	many := make([]CommandAck, 700)
	d.requeueAcks(many)
	if n := len(d.GetAndClearAcks()); n != 500 {
		t.Fatalf("requeue bound: %d", n)
	}
}
