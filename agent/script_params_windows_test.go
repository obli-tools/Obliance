//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

const psSecret = `p@ss'w"rd $x;&|`

// Real runs through powershell.exe (and pwsh when installed): the splat
// wrapper, coercions, defaults, exit codes, and the secret staying out of the
// script file and of every command line.
func psRuntimes(t *testing.T) []string {
	rts := []string{"powershell"}
	if _, err := exec.LookPath("pwsh"); err == nil {
		rts = append(rts, "pwsh")
	} else {
		t.Log("pwsh not installed: Windows PowerShell only")
	}
	return rts
}

const psTypedScript = `param(
  [Parameter(Mandatory=$true)][SecureString]$Pwd,
  [string]$S,
  [int]$N,
  [bool]$B,
  [switch]$Sw,
  [string[]]$Arr,
  [string]$Opt = 'dflt'
)
$plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pwd))
$expected = $env:OBLI_PARAM_PWD
if ($plain -eq $expected -and $plain.Length -gt 0) { 'PWD=OK' } else { 'PWD=BAD' }
"S=$S"
"N=$($N.GetType().Name):$N"
"B=$($B.GetType().Name):$B"
"SW=$($Sw.IsPresent)"
"ARR=$($Arr.Count):$($Arr -join ';')"
"OPT=$Opt"
"PH={{PARAM_S}}"
$ph = "{{PARAM_Pwd}}"
if ($ph -eq $expected) { 'PHSECRET=ENVREF' } else { 'PHSECRET=BAD' }
$self = [IO.File]::ReadAllText($MyInvocation.MyCommand.Path)
if ($self.Contains($expected)) { 'FILE=LEAK' } else { 'FILE=CLEAN' }
if ([Environment]::CommandLine.Contains($expected)) { 'CMDLINE=LEAK' } else { 'CMDLINE=CLEAN' }
exit 0
`

func TestScriptParamsPowerShellTyped(t *testing.T) {
	for _, rt := range psRuntimes(t) {
		res, err := ExecuteScript(ScriptCommand{
			ID: "t-typed-" + rt, Runtime: rt, Content: psTypedScript, TimeoutSeconds: 120,
			Parameters: map[string]any{
				"Pwd": psSecret, "S": "hello world", "N": float64(42), "B": false, "Sw": true,
				"Arr": []interface{}{"a", "b c"},
			},
			SecretNames: []string{"Pwd"},
			ParamOrder:  []string{"Pwd", "S", "N", "B", "Sw", "Arr", "Opt"},
		})
		if err != nil {
			t.Fatalf("%s: %v", rt, err)
		}
		out := strings.ReplaceAll(res.Stdout, "\r", "")
		for _, want := range []string{
			"PWD=OK", "S=hello world", "N=Int32:42", "B=Boolean:False", "SW=True",
			"ARR=2:a;b c", "OPT=dflt", "PH=hello world", "PHSECRET=ENVREF",
			"FILE=CLEAN", "CMDLINE=CLEAN",
		} {
			if !strings.Contains(out, want+"\n") {
				t.Errorf("%s: missing %q in\n%s\nstderr: %s", rt, want, out, res.Stderr)
			}
		}
		if strings.Contains(res.Stdout+res.Stderr, psSecret) {
			t.Errorf("%s: secret printed", rt)
		}
		if res.ExitCode != 0 {
			t.Errorf("%s: exit %d, stderr %s", rt, res.ExitCode, res.Stderr)
		}
	}
}

func TestScriptParamsPowerShellSingleArrayAndTrueBool(t *testing.T) {
	script := "param([string[]]$Arr, [bool]$B, [double]$D)\n\"ARR=$($Arr.Count):$($Arr -join ';')\"\n\"B=$B\"\n\"D=$($D.GetType().Name):$D\"\n"
	res, err := ExecuteScript(ScriptCommand{ID: "t-arr", Runtime: "powershell", Content: script, TimeoutSeconds: 60,
		Parameters: map[string]any{"Arr": []interface{}{"only"}, "B": "yes", "D": 1.5}})
	if err != nil {
		t.Fatal(err)
	}
	out := strings.ReplaceAll(res.Stdout, "\r", "")
	for _, want := range []string{"ARR=1:only", "B=True", "D=Double:1.5"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s / %s", want, out, res.Stderr)
		}
	}
}

func TestScriptParamsPowerShellExitCodes(t *testing.T) {
	params := map[string]any{"X": "1"}
	cases := []struct {
		name, body string
		want       int
	}{
		{"exit3", "param($X)\n'out'\nexit 3\n", 3},
		{"throw", "param($X)\nthrow 'boom'\n", 1},
		{"normal", "param($X)\n'fine'\n", 0},
		{"nativeFailNoExit", "param($X)\ncmd /c exit 5\n", 0},
		{"nonTerminatingError", "param($X)\nWrite-Error 'soft'\n", 0},
		{"exit0", "param($X)\nexit 0\n", 0},
		{"badBinding", "param([int]$X)\n'never'\n", 1},
	}
	for _, rt := range psRuntimes(t) {
		for _, c := range cases {
			p := params
			if c.name == "badBinding" {
				p = map[string]any{"X": "not-a-number"}
			}
			withParams, err := ExecuteScript(ScriptCommand{ID: "t-ec", Runtime: rt, Content: c.body, TimeoutSeconds: 60, Parameters: p})
			if err != nil {
				t.Fatalf("%s/%s: %v", rt, c.name, err)
			}
			if withParams.ExitCode != c.want {
				t.Errorf("%s/%s: wrapper exit %d want %d (stderr %s)", rt, c.name, withParams.ExitCode, c.want, withParams.Stderr)
			}
			if c.name == "throw" && !strings.Contains(withParams.Stderr, "boom") {
				t.Errorf("%s: terminating error on stderr, got %q", rt, withParams.Stderr)
			}
			if c.name == "badBinding" {
				continue // no -File equivalent without passing the value
			}
			// Same script without parameters: plain -File, same exit code.
			plain, err := ExecuteScript(ScriptCommand{ID: "t-ec2", Runtime: rt, Content: c.body, TimeoutSeconds: 60})
			if err != nil {
				t.Fatal(err)
			}
			if plain.ExitCode != withParams.ExitCode {
				t.Errorf("%s/%s: -File exit %d, wrapper exit %d", rt, c.name, plain.ExitCode, withParams.ExitCode)
			}
		}
	}
}

func TestScriptParamsNoParamBlockEnvOnly(t *testing.T) {
	res, err := ExecuteScript(ScriptCommand{ID: "t-env", Runtime: "powershell", TimeoutSeconds: 60,
		Content:    "\"FOO=$env:OBLI_PARAM_FOO\"\n\"SEC=$($env:OBLI_PARAM_SEC.Length)\"\n",
		Parameters: map[string]any{"Foo": "bar", "Sec": "abc"}, SecretNames: []string{"Sec"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, "FOO=bar") || !strings.Contains(res.Stdout, "SEC=3") || res.ExitCode != 0 {
		t.Errorf("got %q / %q / %d", res.Stdout, res.Stderr, res.ExitCode)
	}
}

func TestScriptParamsCmdEnv(t *testing.T) {
	res, err := ExecuteScript(ScriptCommand{ID: "t-cmd", Runtime: "cmd", TimeoutSeconds: 60,
		Content:    "@echo off\r\necho V=%OBLI_PARAM_NAME%\r\necho P={{PARAM_Name}}\r\nif \"{{PARAM_Pwd}}\"==\"%OBLI_PARAM_PWD%\" echo SEC=REF\r\n",
		Parameters: map[string]any{"Name": "x y", "Pwd": "zz"}, SecretNames: []string{"Pwd"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"V=x y", "P=x y", "SEC=REF"} {
		if !strings.Contains(res.Stdout, want) {
			t.Errorf("missing %q in %q", want, res.Stdout)
		}
	}
}

// The JavaScriptSerializer fallback (PowerShell 2.0 has no ConvertFrom-Json),
// forced on this machine's PowerShell.
func TestScriptParamsWrapperJSONFallback(t *testing.T) {
	dir := t.TempDir()
	script := dir + `\s.ps1`
	if err := os.WriteFile(script, []byte("param([string[]]$Arr)\n\"ARR=$($Arr.Count):$($Arr -join ';')\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := psParamWrapper(script, "")
	forced := strings.Replace(w, "if (Get-Command -Name ConvertFrom-Json -ErrorAction SilentlyContinue)", "if ($false)", 1)
	if forced == w {
		t.Fatal("fallback switch not found")
	}
	wrapper := dir + `\w.ps1`
	if err := os.WriteFile(wrapper, []byte(psWrapperBOM+forced), 0o600); err != nil {
		t.Fatal(err)
	}
	c := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", wrapper)
	c.Env = scriptParamEnv(map[string]interface{}{"Arr": []interface{}{"a", "b c", `q"uote`}}, os.Environ())
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(string(out), `ARR=3:a;b c;q"uote`) {
		t.Errorf("got %s", out)
	}
}
