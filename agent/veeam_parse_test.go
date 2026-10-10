package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParseVeeamJobLines(t *testing.T) {
	fields := []string{"6d3c...-id", "Backup | DC01\nnight", "Backup", "Working", "Success", "True",
		"2026-09-30T22:00:00.0000000Z", "", "2026-10-01T22:00:00.0000000Z", "42", "123456789012", "98765", "3600", "Repo é", ""}
	enc := make([]string, len(fields))
	for i, f := range fields {
		enc[i] = b64(f)
	}
	out := utf8BOM + "WARNING: something\r\n" + veeamJobLinePrefix + strings.Join(enc, "|") + "\r\n\r\n"
	jobs, err := parseVeeamJobLines(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("jobs = %+v", jobs)
	}
	j := jobs[0]
	if j.Name != "Backup | DC01\nnight" || j.RawState != "Working" || !j.ScheduleEnabled || j.ProgressPercent != 42 ||
		j.ProcessedBytes != 123456789012 || j.TransferredBytes != 98765 || j.DurationSeconds != 3600 || j.Repository != "Repo é" ||
		j.LastRunEnd != "" || j.NextRun != "2026-10-01T22:00:00.0000000Z" {
		t.Errorf("job = %+v", j)
	}

	if jobs, err := parseVeeamJobLines(""); err != nil || jobs == nil || len(jobs) != 0 {
		t.Errorf("empty: %v %v", jobs, err)
	}
	if _, err := parseVeeamJobLines(veeamJobLinePrefix + "YQ==|YQ=="); err == nil {
		t.Error("short line must fail")
	}
	if _, err := parseVeeamJobLines(veeamJobLinePrefix + strings.Repeat("!!|", 14) + "!!"); err == nil {
		t.Error("bad base64 must fail")
	}
}
