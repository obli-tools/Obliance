package main

import (
	"strconv"
	"strings"
)

// psUTF8Prefix is prepended to all PowerShell commands to force UTF-8 output encoding.
// Without this, non-ASCII characters (accents, special chars) are garbled on non-English
// Windows where the default console encoding is CP850/CP1252.
//
// Must stay valid on Windows PowerShell 2.0 (Windows 7 / Server 2008 R2): the
// `[Type]::new()` syntax is PowerShell 5+ only, New-Object works everywhere.
// `UTF8Encoding $false` = no BOM, exactly what `[System.Text.UTF8Encoding]::new()`
// produced before.
const psUTF8Prefix = "[Console]::OutputEncoding=(New-Object System.Text.UTF8Encoding $false);$OutputEncoding=[Console]::OutputEncoding;"

// psVersionScript prints the PowerShell engine version ("2.0", "5.1.17763.1").
// $PSVersionTable exists since PowerShell 2.0.
const psVersionScript = "$PSVersionTable.PSVersion.ToString()"

// parsePSVersion extracts the version string and its major number from the
// output of psVersionScript (BOM / blank lines / CRLF tolerated). It returns
// ("", 0) when the output is not a dotted version.
func parsePSVersion(out string) (string, int) {
	out = strings.TrimPrefix(out, utf8BOM)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, utf8BOM))
		if line == "" {
			continue
		}
		major, _, ok := strings.Cut(line, ".")
		if !ok {
			return "", 0
		}
		n, err := strconv.Atoi(major)
		if err != nil || n <= 0 || n > 99 {
			return "", 0
		}
		for _, part := range strings.Split(line, ".") {
			if _, err := strconv.Atoi(part); err != nil {
				return "", 0
			}
		}
		return line, n
	}
	return "", 0
}

// utf8BOM is the byte-order mark Windows PowerShell may prefix to its output.
var utf8BOM = string(rune(0xFEFF))
