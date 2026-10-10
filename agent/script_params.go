package main

// ── Script parameters (run_script) ───────────────────────────────────────────
//
// Payload fields consumed (server ≥ script-parameters release):
//   - parameters            map name → value (string | number | bool | []string),
//                           secret values included (decrypted by the server
//                           only when the command is handed to the agent);
//   - secretParameterNames  []string: the names whose value is secret;
//   - parameterOrder        []string: every declared parameter, definition order.
// A raw command (POST /api/commands, older servers) may omit the last two:
// nothing is then treated as secret and the order is the sorted keys.
//
// How a script receives its values:
//   1. Every value is exported to the script process as the environment
//      variable OBLI_PARAM_<UPPERCASE NAME> (strings as is, numbers without a
//      trailing ".0", booleans "true"/"false", multiselect arrays as a JSON
//      array string). Only for the script process (exec.Cmd.Env) and the
//      processes it starts — never the agent's own environment.
//   2. PowerShell / pwsh: when at least one value is given, the script runs
//      through a small wrapper (psParamWrapper) that splats the values onto
//      the parameters the script DECLARES in its param() block, coerced by
//      their declared type (SecureString, switch, bool, numbers, arrays...).
//      No value ever appears on a command line.
//   3. bash / sh / zsh: also positional arguments $1..$n — every NON-secret
//      parameter of parameterOrder, its value or "" when absent (arrays
//      comma-joined). Secrets are never positional: positions count the
//      non-secret parameters only.
//   4. cmd: %OBLI_PARAM_NAME%; python / perl / ruby: the environment.
//   5. Backward compatibility: {{PARAM_name}} placeholders in the script text
//      are still replaced — by the value for NON-secret parameters only. A
//      secret placeholder is replaced by a reference to its environment
//      variable ($env:OBLI_PARAM_X / ${OBLI_PARAM_X} / %OBLI_PARAM_X%; empty
//      for other runtimes): a secret is never written into the temp file.

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const scriptParamEnvPrefix = "OBLI_PARAM_"

// psWrapperBOM: UTF-8 byte order mark of the wrapper file.
const psWrapperBOM = "\xEF\xBB\xBF"

var (
	scriptParamNameRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	scriptPlaceholderRE = regexp.MustCompile(`\{\{PARAM_([A-Za-z0-9_]+)\}\}`)
)

// scriptParamEnvName: OBLI_PARAM_<UPPERCASE NAME>.
func scriptParamEnvName(name string) string {
	return scriptParamEnvPrefix + strings.ToUpper(name)
}

// payloadStringList reads a []string from a decoded JSON payload field.
func payloadStringList(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		if s, ok := v.([]string); ok {
			return append([]string(nil), s...)
		}
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// isSecretParam: name listed in secretNames (case-insensitive).
func isSecretParam(name string, secretNames []string) bool {
	for _, s := range secretNames {
		if strings.EqualFold(s, name) {
			return true
		}
	}
	return false
}

func formatParamNumber(f float64) string {
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// paramScalarText: text of a scalar value; ok=false for arrays / unknown types.
func paramScalarText(v interface{}) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", true
	case string:
		return x, true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	case float64:
		return formatParamNumber(x), true
	case float32:
		return formatParamNumber(float64(x)), true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case json.Number:
		return x.String(), true
	}
	return "", false
}

func paramList(v interface{}) ([]string, bool) {
	switch x := v.(type) {
	case []string:
		return x, true
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := paramScalarText(e)
			if !ok {
				s = fmt.Sprintf("%v", e)
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// paramText: value as text for substitution / positional args (arrays
// comma-joined).
func paramText(v interface{}) string {
	if s, ok := paramScalarText(v); ok {
		return s
	}
	if l, ok := paramList(v); ok {
		return strings.Join(l, ",")
	}
	return fmt.Sprintf("%v", v)
}

// paramEnvValue: value as exported in OBLI_PARAM_* (arrays as JSON).
func paramEnvValue(v interface{}) string {
	var s string
	if l, ok := paramList(v); ok {
		b, _ := json.Marshal(l)
		s = string(b)
	} else {
		s = paramText(v)
	}
	// A NUL byte cannot travel in an environment block.
	return strings.ReplaceAll(s, "\x00", "")
}

// scriptParamEnv returns base (normally os.Environ()) without any inherited
// OBLI_PARAM_* variable, plus one OBLI_PARAM_<NAME> per parameter with a
// valid identifier name. Nil when there is no parameter (inherit as today).
func scriptParamEnv(params map[string]interface{}, base []string) []string {
	if len(params) == 0 {
		return nil
	}
	env := make([]string, 0, len(base)+len(params))
	for _, kv := range base {
		if len(kv) >= len(scriptParamEnvPrefix) && strings.EqualFold(kv[:len(scriptParamEnvPrefix)], scriptParamEnvPrefix) {
			continue
		}
		env = append(env, kv)
	}
	names := make([]string, 0, len(params))
	for k := range params {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if !scriptParamNameRE.MatchString(k) {
			continue
		}
		env = append(env, scriptParamEnvName(k)+"="+paramEnvValue(params[k]))
	}
	return env
}

// lookupParam: value by name, exact match first then case-insensitive.
func lookupParam(params map[string]interface{}, name string) (string, interface{}, bool) {
	if v, ok := params[name]; ok {
		return name, v, true
	}
	for k, v := range params {
		if strings.EqualFold(k, name) {
			return k, v, true
		}
	}
	return "", nil, false
}

// secretPlaceholderRef: what replaces a SECRET {{PARAM_x}} placeholder — a
// reference to its environment variable in the script's language, never the
// value.
func secretPlaceholderRef(runtimeName, name string) string {
	env := scriptParamEnvName(name)
	switch strings.ToLower(runtimeName) {
	case "powershell", "pwsh":
		return "$env:" + env
	case "bash", "sh", "zsh":
		return "${" + env + "}"
	case "cmd", "batch":
		return "%" + env + "%"
	}
	return ""
}

// applyParameters replaces {{PARAM_name}} placeholders (name matched
// case-insensitively): by the value for a NON-secret parameter, by a
// reference to its environment variable for a secret one (see
// secretPlaceholderRef). Placeholders of unknown names are left untouched.
func applyParameters(content, runtimeName string, params map[string]interface{}, secretNames []string) string {
	if len(params) == 0 || !strings.Contains(content, "{{PARAM_") {
		return content
	}
	return scriptPlaceholderRE.ReplaceAllStringFunc(content, func(m string) string {
		name := scriptPlaceholderRE.FindStringSubmatch(m)[1]
		key, v, ok := lookupParam(params, name)
		if !ok {
			return m
		}
		if isSecretParam(key, secretNames) {
			return secretPlaceholderRef(runtimeName, key)
		}
		return paramText(v)
	})
}

// effectiveParamOrder: parameterOrder when given, else the sorted keys.
func effectiveParamOrder(params map[string]interface{}, order []string) []string {
	if len(order) > 0 {
		return order
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// scriptPositionalArgs: shell runtimes only — every NON-secret parameter of
// the order, its value or "" when absent. Secrets are never positional.
func scriptPositionalArgs(runtimeName string, params map[string]interface{}, secretNames, order []string) []string {
	switch strings.ToLower(runtimeName) {
	case "bash", "sh", "zsh":
	default:
		return nil
	}
	if len(params) == 0 && len(order) == 0 {
		return nil
	}
	var args []string
	for _, name := range effectiveParamOrder(params, order) {
		if isSecretParam(name, secretNames) {
			continue
		}
		if _, v, ok := lookupParam(params, name); ok {
			args = append(args, strings.ReplaceAll(paramText(v), "\x00", ""))
		} else {
			args = append(args, "")
		}
	}
	return args
}

// psSingleQuote: a PowerShell single-quoted literal.
func psSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// psParamWrapperBody is the PowerShell wrapper that passes OBLI_PARAM_*
// values to the parameters the script declares. Compatible with Windows
// PowerShell 2.0 → 5.1 and pwsh 7 (no ConvertFrom-Json dependency: falls
// back to JavaScriptSerializer of System.Web.Extensions, .NET 3.5+).
//   - declared parameters: (Get-Command -Name <path> -CommandType ExternalScript).Parameters
//     (no -LiteralPath on PS 2.0; temp paths carry no wildcard character);
//   - coercion by ParameterType: SecureString (ConvertTo-SecureString
//     -AsPlainText -Force), SwitchParameter / Boolean ('true','1','yes','on','y'),
//     arrays (JSON array or single element, then converted to the declared
//     array type), anything else LanguagePrimitives.ConvertTo. PSCredential
//     parameters are skipped (no value form for them);
//   - exit code, same as `powershell -File script.ps1` (verified on Windows
//     PowerShell 5.1 and pwsh 7): `exit N` → N; uncaught terminating error
//     → 1 (error printed on stderr); normal end → 0, even when the last
//     native command failed. A script that ran `exit N` (N ≠ 0) leaves $? =
//     $false right after the `&` call; a normal end leaves $? = $true.
//   - a value that cannot be converted → error on stderr, exit 1 (as a
//     parameter binding error under -File).
//
// Wrapper variables / functions are prefixed __obli (the script runs in a
// child scope and can see them).
const psParamWrapperBody = `$__obliSplat = @{}
$__obliCmd = $null
try { $__obliCmd = Get-Command -Name $__obliPath -CommandType ExternalScript -ErrorAction Stop } catch { $__obliCmd = $null }
function __obliBool([string]$s) { return @('true','1','yes','on','y') -contains $s.Trim().ToLower() }
function __obliJsonArray([string]$s) {
  if (Get-Command -Name ConvertFrom-Json -ErrorAction SilentlyContinue) { $__obliJ = ConvertFrom-Json -InputObject $s }
  else {
    Add-Type -AssemblyName System.Web.Extensions
    $__obliJ = (New-Object System.Web.Script.Serialization.JavaScriptSerializer).DeserializeObject($s)
  }
  $__obliR = New-Object System.Collections.ArrayList
  foreach ($__obliE in $__obliJ) { [void]$__obliR.Add($__obliE) }
  return ,($__obliR.ToArray())
}
if ($__obliCmd -ne $null -and $__obliCmd.Parameters -ne $null) {
  foreach ($__obliP in @($__obliCmd.Parameters.Values)) {
    $__obliV = [Environment]::GetEnvironmentVariable('OBLI_PARAM_' + $__obliP.Name.ToUpperInvariant())
    if ($__obliV -eq $null) { continue }
    $__obliT = $__obliP.ParameterType
    try {
      if ($__obliT -eq [System.Security.SecureString]) {
        if ($__obliV -eq '') { $__obliSplat[$__obliP.Name] = New-Object System.Security.SecureString }
        else { $__obliSplat[$__obliP.Name] = ConvertTo-SecureString -String $__obliV -AsPlainText -Force }
      } elseif ($__obliT -eq [System.Management.Automation.SwitchParameter]) {
        $__obliSplat[$__obliP.Name] = [switch](__obliBool $__obliV)
      } elseif ($__obliT -eq [bool]) {
        $__obliSplat[$__obliP.Name] = [bool](__obliBool $__obliV)
      } elseif ($__obliT -eq [System.Management.Automation.PSCredential]) {
        continue
      } elseif ($__obliT.IsArray) {
        if ($__obliV.TrimStart().StartsWith('[')) { $__obliA = __obliJsonArray $__obliV } else { $__obliA = @($__obliV) }
        $__obliSplat[$__obliP.Name] = [System.Management.Automation.LanguagePrimitives]::ConvertTo($__obliA, $__obliT)
      } else {
        $__obliSplat[$__obliP.Name] = [System.Management.Automation.LanguagePrimitives]::ConvertTo($__obliV, $__obliT)
      }
    } catch {
      [Console]::Error.WriteLine("Parameter '" + $__obliP.Name + "': " + $_.Exception.Message)
      exit 1
    }
  }
}
Remove-Variable -Name __obliV, __obliP, __obliT, __obliA -ErrorAction SilentlyContinue
$global:LASTEXITCODE = 0
$__obliOk = $true
try {
  & $__obliPath @__obliSplat
  $__obliOk = $?
} catch {
  [Console]::Error.WriteLine(($_ | Out-String))
  exit 1
}
if ((-not $__obliOk) -and $LASTEXITCODE) { exit $LASTEXITCODE }
exit 0
`

// psParamWrapper returns the wrapper script for scriptPath. tlsPreamble
// (psTLS12Preamble on PowerShell < 5, else "") is its first line: with the
// wrapper, a param() script gets TLS 1.2 too. The script path is embedded as
// a single-quoted literal; no parameter value is ever written in it.
func psParamWrapper(scriptPath, tlsPreamble string) string {
	return tlsPreamble + "$__obliPath = " + psSingleQuote(scriptPath) + "\n" + psParamWrapperBody
}

// writePSParamWrapper writes the wrapper next to the system temp dir, UTF-8
// with BOM (Windows PowerShell 5.1 reads a BOM-less file as ANSI). The
// caller removes it.
func writePSParamWrapper(scriptPath, tlsPreamble string) (string, error) {
	f, err := os.CreateTemp("", "obliwrap-*.ps1")
	if err != nil {
		return "", fmt.Errorf("create wrapper: %w", err)
	}
	p := f.Name()
	_, werr := f.WriteString(psWrapperBOM + psParamWrapper(scriptPath, tlsPreamble))
	cerr := f.Close()
	if werr != nil || cerr != nil {
		os.Remove(p)
		if werr == nil {
			werr = cerr
		}
		return "", fmt.Errorf("write wrapper: %w", werr)
	}
	return p, nil
}
