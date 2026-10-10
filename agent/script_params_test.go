package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestScriptParamEnv(t *testing.T) {
	if got := scriptParamEnv(nil, []string{"A=1"}); got != nil {
		t.Fatalf("no parameter: inherit (nil), got %v", got)
	}
	base := []string{"PATH=/bin", "OBLI_PARAM_OLD=leak", "obli_param_lower=leak2", "HOME=/root"}
	params := map[string]interface{}{
		"Name":     "hello world",
		"count":    float64(42),
		"ratio":    1.5,
		"Force":    true,
		"off":      false,
		"Tags":     []interface{}{"a", "b c"},
		"bad=name": "x",
		"nul":      "a\x00b",
	}
	env := scriptParamEnv(params, base)
	want := map[string]string{
		"OBLI_PARAM_NAME":  "hello world",
		"OBLI_PARAM_COUNT": "42",
		"OBLI_PARAM_RATIO": "1.5",
		"OBLI_PARAM_FORCE": "true",
		"OBLI_PARAM_OFF":   "false",
		"OBLI_PARAM_TAGS":  `["a","b c"]`,
		"OBLI_PARAM_NUL":   "ab",
	}
	got := map[string]string{}
	for _, kv := range env {
		i := strings.IndexByte(kv, '=')
		got[kv[:i]] = kv[i+1:]
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["OBLI_PARAM_OLD"]; ok {
		t.Error("inherited OBLI_PARAM_* must be dropped")
	}
	if _, ok := got["obli_param_lower"]; ok {
		t.Error("inherited obli_param_* (any case) must be dropped")
	}
	if got["PATH"] != "/bin" || got["HOME"] != "/root" {
		t.Error("base environment kept")
	}
	for k := range got {
		if strings.Contains(k, "BAD") {
			t.Errorf("invalid name exported: %s", k)
		}
	}
}

func TestApplyParametersSecretNeverSubstituted(t *testing.T) {
	params := map[string]interface{}{"Pwd": "S3cr3t!", "User": "bob", "N": float64(3), "L": []interface{}{"x", "y"}}
	secrets := []string{"pwd"}
	content := `u={{PARAM_User}} n={{PARAM_n}} l={{PARAM_L}} p={{PARAM_Pwd}} z={{PARAM_Unknown}}`
	cases := map[string]string{
		"powershell": `u=bob n=3 l=x,y p=$env:OBLI_PARAM_PWD z={{PARAM_Unknown}}`,
		"pwsh":       `u=bob n=3 l=x,y p=$env:OBLI_PARAM_PWD z={{PARAM_Unknown}}`,
		"bash":       `u=bob n=3 l=x,y p=${OBLI_PARAM_PWD} z={{PARAM_Unknown}}`,
		"cmd":        `u=bob n=3 l=x,y p=%OBLI_PARAM_PWD% z={{PARAM_Unknown}}`,
		"python":     `u=bob n=3 l=x,y p= z={{PARAM_Unknown}}`,
	}
	for rt, want := range cases {
		got := applyParameters(content, rt, params, secrets)
		if got != want {
			t.Errorf("%s: got %q want %q", rt, got, want)
		}
		if strings.Contains(got, "S3cr3t!") {
			t.Errorf("%s: secret substituted", rt)
		}
	}
	// No secret list (raw command / older server): plain substitution.
	if got := applyParameters("{{PARAM_Pwd}}", "bash", params, nil); got != "S3cr3t!" {
		t.Errorf("legacy substitution: %q", got)
	}
	if got := applyParameters("none", "bash", nil, nil); got != "none" {
		t.Error("no params: unchanged")
	}
}

func TestScriptPositionalArgs(t *testing.T) {
	params := map[string]interface{}{"a": "1", "secret": "S", "c": []interface{}{"x", "y"}, "d": true}
	order := []string{"a", "b", "secret", "c", "d"}
	got := scriptPositionalArgs("bash", params, []string{"secret"}, order)
	want := []string{"1", "", "x,y", "true"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	for _, rt := range []string{"powershell", "cmd", "python", "perl", "ruby"} {
		if a := scriptPositionalArgs(rt, params, nil, order); a != nil {
			t.Errorf("%s: no positional args, got %v", rt, a)
		}
	}
	// No order (raw command): sorted keys, still no secret.
	got = scriptPositionalArgs("sh", params, []string{"secret"}, nil)
	if !reflect.DeepEqual(got, []string{"1", "x,y", "true"}) {
		t.Errorf("sorted fallback: %q", got)
	}
	if a := scriptPositionalArgs("zsh", nil, nil, nil); a != nil {
		t.Errorf("no params: %v", a)
	}
}

func TestPSParamWrapperGeneration(t *testing.T) {
	w := psParamWrapper(`C:\Temp\it's\obliscript-1.ps1`, "")
	if !strings.HasPrefix(w, `$__obliPath = 'C:\Temp\it''s\obliscript-1.ps1'`+"\n") {
		t.Fatalf("path literal: %q", w[:60])
	}
	for _, must := range []string{"ConvertTo-SecureString", "& $__obliPath @__obliSplat", "JavaScriptSerializer", "OBLI_PARAM_", "exit $LASTEXITCODE"} {
		if !strings.Contains(w, must) {
			t.Errorf("wrapper lacks %q", must)
		}
	}
	tw := psParamWrapper("p.ps1", psTLS12Preamble)
	if !strings.HasPrefix(tw, psTLS12Preamble) {
		t.Error("TLS preamble first")
	}
}

func TestPayloadStringList(t *testing.T) {
	if got := payloadStringList([]interface{}{"a", 1, "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("got %v", got)
	}
	if payloadStringList(nil) != nil || payloadStringList("x") != nil {
		t.Error("non-list → nil")
	}
	if !isSecretParam("PWD", []string{"pwd"}) || isSecretParam("x", nil) {
		t.Error("isSecretParam")
	}
	if formatParamNumber(42) != "42" || formatParamNumber(-1.25) != "-1.25" {
		t.Error("formatParamNumber")
	}
}
