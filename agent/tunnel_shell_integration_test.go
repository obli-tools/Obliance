package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestCmdPromptValue(t *testing.T) {
	cases := map[string]string{
		"":             `$e]9;9;$P$e\$P$G`,
		"$P$G":         `$e]9;9;$P$e\$P$G`,
		"[$T] $P$_$G ": `$e]9;9;$P$e\[$T] $P$_$G `,
	}
	for in, want := range cases {
		if got := cmdPromptValue(in); got != want {
			t.Errorf("cmdPromptValue(%q) = %q, want %q", in, got, want)
		}
		if again := cmdPromptValue(cmdPromptValue(in)); again != want {
			t.Errorf("cmdPromptValue twice (%q) = %q: not idempotent", in, again)
		}
	}
}

func TestEnvWith(t *testing.T) {
	env := []string{"=C:=C:\\Windows", "Path=C:\\bin", "prompt=$T$G", "TEMP=C:\\t", "PROMPT=dup"}
	got := envWith(env, "PROMPT", "x")
	want := []string{"=C:=C:\\Windows", "Path=C:\\bin", "PROMPT=x", "TEMP=C:\\t"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("envWith replace = %q, want %q (in place, case ignored, duplicate dropped, order kept)", got, want)
	}
	got = envWith([]string{"A=1", "=D:=D:\\"}, "PROMPT", "y")
	if strings.Join(got, "|") != "A=1|=D:=D:\\|PROMPT=y" {
		t.Fatalf("envWith append = %q", got)
	}
	if v, ok := envValue(env, "Prompt"); !ok || v != "$T$G" {
		t.Fatalf("envValue = %q %v, want the first PROMPT whatever its case", v, ok)
	}
	if _, ok := envValue(env, "C:"); ok {
		t.Fatal("envValue must not take a hidden per-drive entry (=C:) for C:")
	}
	if v, ok := envValue(env, "=C:"); !ok || v != "C:\\Windows" {
		t.Fatalf("envValue(=C:) = %q %v", v, ok)
	}
	if env[2] != "prompt=$T$G" {
		t.Fatal("envWith changed its input")
	}
}

func TestUTF16EnvBlock(t *testing.T) {
	b, err := utf16EnvBlock([]string{"A=1", "", "PROMPT=é"})
	if err != nil {
		t.Fatal(err)
	}
	want := append(append(utf16.Encode([]rune("A=1")), 0), append(utf16.Encode([]rune("PROMPT=é")), 0, 0)...)
	if len(b) != len(want) {
		t.Fatalf("block %v, want %v", b, want)
	}
	for i := range want {
		if b[i] != want[i] {
			t.Fatalf("block %v, want %v (an empty entry left out, a double NUL at the end)", b, want)
		}
	}
	if b[len(b)-1] != 0 || b[len(b)-2] != 0 {
		t.Fatal("the block must end with a double NUL")
	}
	if _, err := utf16EnvBlock([]string{"A=1", "B=x\x00y"}); err == nil {
		t.Fatal("an entry holding a NUL must be refused")
	}
	if e, _ := utf16EnvBlock(nil); len(e) != 2 || e[0] != 0 || e[1] != 0 {
		t.Fatalf("an empty environment: %v, want two NULs", e)
	}
}

func TestPSIntegrationCommand(t *testing.T) {
	c := psIntegrationCommand
	if strings.ContainsAny(c, "\"\r\n`") {
		t.Fatal("the PowerShell command travels inside \"...\" on one command line: no double quote, backtick or line break")
	}
	if strings.HasSuffix(c, `\`) {
		t.Fatal("a backslash before the closing quote would escape it")
	}
	for _, want := range []string{"]9;9;", "try {", "catch {}", "-not $global:__oblianceSI -and $function:prompt", "& $global:__oblianceP",
		"$l.Provider.Name -eq 'FileSystem'", "-notmatch '[\\x00-\\x1f\\x7f-\\x9f]'", "[char]27 + '\\' + $r"} {
		if !strings.Contains(c, want) {
			t.Errorf("the PowerShell command lacks %q", want)
		}
	}
	// The user's prompt runs first (its $? intact), then the location is read.
	if strings.Index(c, "& $global:__oblianceP") > strings.Index(c, "CurrentLocation") {
		t.Error("the user's prompt must run before anything else in the wrapper")
	}
	// Balanced braces and parentheses (a parse error would print at every start).
	for _, p := range [][2]string{{"{", "}"}, {"(", ")"}} { // (brackets: the OSC itself opens with "]")
		if strings.Count(c, p[0]) != strings.Count(c, p[1]) {
			t.Errorf("unbalanced %s%s in the PowerShell command", p[0], p[1])
		}
	}
	if l := psCommandLine(); !strings.HasPrefix(l, `powershell.exe -NoLogo -NoExit -Command "`) || !strings.HasSuffix(l, `"`) || strings.Count(l, `"`) != 2 {
		t.Fatalf("command line %q", l)
	}
}

func TestBashIntegrationScript(t *testing.T) {
	s := bashIntegration
	if strings.Contains(s, "\r") {
		t.Fatal("the bash rcfile must have LF line ends only")
	}
	if !strings.HasPrefix(s, "# Obliance agent") || !strings.Contains(s, `if [ -z "${__OBLIANCE_SI:-}" ]; then`) || !strings.HasSuffix(s, "fi\n") {
		t.Fatal("the rcfile must be commented and guarded (read once)")
	}
	// The login files, in bash --login's order, the first of the three only.
	order := []string{"[ -r /etc/profile ] && . /etc/profile", "if [ -r ~/.bash_profile ]; then . ~/.bash_profile", "elif [ -r ~/.bash_login ]; then . ~/.bash_login", "elif [ -r ~/.profile ]; then . ~/.profile"}
	last := -1
	for _, o := range order {
		i := strings.Index(s, o)
		if i <= last {
			t.Fatalf("login file %q missing or out of order", o)
		}
		last = i
	}
	if strings.Index(s, "trap ") > strings.Index(s, "/etc/profile") {
		t.Error("the .bash_logout trap is set before the login files (a user's own EXIT trap wins)")
	}
	// set -u in a user's files breaks nothing: every variable that may be unset is read with :-.
	if m := regexp.MustCompile(`\$(HOME|PWD|HOSTNAME|PROMPT_COMMAND|__OBLIANCE_SI|1)\b|\$\{(HOME|PWD|HOSTNAME|PROMPT_COMMAND|__OBLIANCE_SI|1)\}`).FindString(s); m != "" {
		t.Errorf("unguarded variable %s (set -u)", m)
	}
	if strings.Contains(s, "$HOME") || strings.Contains(s, "${HOME") {
		t.Error("the home folder is ~ (bash's own rule when HOME is unset), never $HOME")
	}
	// Bytes, not characters: the encoding runs in a subshell with LC_ALL=C (the shell's locale untouched).
	if !strings.Contains(s, "__obliance_osc7_print() (\n  LC_ALL=C\n") || strings.Contains(s, "local LC_ALL") {
		t.Error("the OSC 7 encoding must run in a subshell with LC_ALL=C")
	}
	if !strings.Contains(s, `printf '\033]7;file://'`) || !strings.Contains(s, `printf '\033\\'`) {
		t.Error("OSC 7 file:// ... ST")
	}
	if !strings.Contains(s, "( PROMPT_COMMAND=__obliance_osc7 ) 2>/dev/null") {
		t.Error("a read-only PROMPT_COMMAND must be left alone")
	}
}

// The script run by a real bash (Linux / macOS: /bin/bash; elsewhere
// OBLIANCE_TEST_BASH=<path of a bash>, e.g. Git for Windows' usr\bin\bash.exe).
func testBash(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("OBLIANCE_TEST_BASH"); p != "" {
		return p
	}
	if runtime.GOOS != "windows" {
		if _, err := os.Stat("/bin/bash"); err == nil {
			return "/bin/bash"
		}
	}
	t.Skip("no bash to run the rcfile (set OBLIANCE_TEST_BASH)")
	return ""
}

// runRC runs the rcfile in bash -c (its /etc/profile replaced by etc, HOME =
// home), then script; returns stdout and stderr.
func runRC(t *testing.T, bash, dir, home, etc, script string) (string, string) {
	t.Helper()
	rc := filepath.Join(dir, "rc.bash")
	body := strings.ReplaceAll(bashIntegration, "/etc/profile", filepath.ToSlash(etc))
	if err := os.WriteFile(rc, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, "--noprofile", "--norc", "-c", `. "$RC"; `+script)
	cmd.Env = append(os.Environ(), "HOME="+filepath.ToSlash(home), "RC="+filepath.ToSlash(rc), "D="+filepath.ToSlash(dir), "LC_ALL=", "LANG=C.UTF-8")
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("bash: %v\nstdout: %q\nstderr: %q", err, out.String(), errb.String())
	}
	return out.String(), errb.String()
}

func TestBashIntegrationRuns(t *testing.T) {
	bash := testBash(t)
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	weird := filepath.Join(dir, "my dir é#%")
	for _, d := range []string{home, weird} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	etc := filepath.Join(dir, "etcprofile")
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(etc, "echo ETC\n")
	write(filepath.Join(home, ".bash_profile"), "echo BASH_PROFILE\nset -u\nPROMPT_COMMAND='echo \"USER_PC rc=$?\"'\ntrap 'echo USER_TRAP' EXIT\n")
	write(filepath.Join(home, ".profile"), "echo PROFILE_NOT_READ\n")
	write(filepath.Join(home, ".bash_logout"), "echo LOGOUT\n")
	out, errOut := runRC(t, bash, dir, home, etc, `cd "$D/my dir é#%" && false; eval "$PROMPT_COMMAND"; . "$RC"; echo "PC=[$PROMPT_COMMAND]"`)
	if errOut != "" {
		t.Errorf("stderr: %q", errOut)
	}
	if !strings.Contains(out, "ETC\nBASH_PROFILE\n") || strings.Contains(out, "PROFILE_NOT_READ") {
		t.Errorf("login files: %q (want /etc/profile then ~/.bash_profile only)", out)
	}
	re := regexp.MustCompile("\x1b\\]7;file://([^/\x1b]*)(/[^\x1b]*)\x1b\\\\USER_PC rc=1\n")
	m := re.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no OSC 7 followed by the user's PROMPT_COMMAND with $? kept: %q", out)
	}
	if !strings.HasSuffix(m[2], "/my%20dir%20%C3%A9%23%25") || strings.ContainsAny(m[2], " #é") {
		t.Errorf("path %q: want every byte outside A-Za-z0-9/._~- percent-encoded", m[2])
	}
	if !regexp.MustCompile(`^[A-Za-z0-9._~%-]*$`).MatchString(m[1]) {
		t.Errorf("host %q not encoded", m[1])
	}
	if !strings.Contains(out, "PC=[__obliance_osc7\necho \"USER_PC rc=$?\"]") {
		t.Errorf("PROMPT_COMMAND: ours first, the user's after, once (the rcfile read twice changes nothing): %q", out)
	}
	if !strings.HasSuffix(out, "USER_TRAP\n") || strings.Contains(out, "LOGOUT") {
		t.Errorf("the user's own EXIT trap wins over the .bash_logout emulation: %q", out)
	}
	// No user trap: ~/.bash_logout at exit; a read-only PROMPT_COMMAND: left alone, silently.
	write(filepath.Join(home, ".bash_profile"), "readonly PROMPT_COMMAND='echo RO'\n")
	out, errOut = runRC(t, bash, dir, home, etc, `echo "PC=[$PROMPT_COMMAND]"`)
	if errOut != "" || !strings.Contains(out, "PC=[echo RO]") || !strings.HasSuffix(out, "LOGOUT\n") {
		t.Errorf("read-only PROMPT_COMMAND / logout: stdout %q stderr %q", out, errOut)
	}
	// Nothing at all in the user's files: ours alone; ~/.profile read when it is the only one.
	os.Remove(filepath.Join(home, ".bash_profile"))
	write(filepath.Join(home, ".profile"), "echo PROFILE\n")
	out, _ = runRC(t, bash, dir, home, etc, `echo "PC=[$PROMPT_COMMAND]"`)
	if !strings.Contains(out, "PROFILE\n") || !strings.Contains(out, "PC=[__obliance_osc7]") {
		t.Errorf("~/.profile alone: %q", out)
	}
}
