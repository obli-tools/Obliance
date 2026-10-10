package main

// Veeam job enumeration output format, PowerShell 2.0-safe (Windows Server
// 2008 R2 runs VBR 9.5 with the VeeamPSSnapIn under PowerShell 2.0, which has
// neither ConvertTo-Json nor [pscustomobject]). The enumeration script prints
// one line per job:
//
//	VJOB|<b64 jobId>|<b64 name>|<b64 jobType>|<b64 rawState>|<b64 lastResult>|
//	     <b64 scheduleEnabled True/False>|<b64 lastRunStart>|<b64 lastRunEnd>|
//	     <b64 nextRun>|<b64 progressPercent>|<b64 processedBytes>|
//	     <b64 transferredBytes>|<b64 durationSeconds>|<b64 repository>|
//	     <b64 description>
//
// (one physical line). Every field is the base64 of its UTF-8 text, so job
// names / descriptions containing "|", newlines or non-ASCII characters
// survive whatever console code page PowerShell writes with. Same format on
// every PowerShell version: one code path, unit-tested here.

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// psJob is one enumerated job, before normalisation into VeeamJob.
type psJob struct {
	JobID            string `json:"jobId"`
	Name             string `json:"name"`
	JobType          string `json:"jobType"`
	RawState         string `json:"rawState"`
	LastResult       string `json:"lastResult"`
	ScheduleEnabled  bool   `json:"scheduleEnabled"`
	LastRunStart     string `json:"lastRunStart"`
	LastRunEnd       string `json:"lastRunEnd"`
	NextRun          string `json:"nextRun"`
	ProgressPercent  int    `json:"progressPercent"`
	ProcessedBytes   int64  `json:"processedBytes"`
	TransferredBytes int64  `json:"transferredBytes"`
	DurationSeconds  int64  `json:"durationSeconds"`
	Repository       string `json:"repository"`
	Description      string `json:"description"`
}

const veeamJobLinePrefix = "VJOB|"
const veeamJobFieldCount = 15

// parseVeeamJobLines decodes the enumeration output. Lines that are not job
// lines (warnings, banners) are ignored; a malformed job line is an error
// (better a visible failure than a silently shorter job list).
func parseVeeamJobLines(out string) ([]psJob, error) {
	jobs := []psJob{}
	for _, line := range strings.Split(strings.TrimPrefix(out, utf8BOM), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, veeamJobLinePrefix) {
			continue
		}
		parts := strings.Split(line[len(veeamJobLinePrefix):], "|")
		if len(parts) != veeamJobFieldCount {
			return nil, fmt.Errorf("veeam job line: %d fields, want %d", len(parts), veeamJobFieldCount)
		}
		f := make([]string, len(parts))
		for i, p := range parts {
			b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
			if err != nil {
				return nil, fmt.Errorf("veeam job line field %d: %w", i, err)
			}
			f[i] = string(b)
		}
		atoi64 := func(s string) int64 {
			n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
			if err != nil {
				return 0
			}
			return n
		}
		jobs = append(jobs, psJob{
			JobID:            f[0],
			Name:             f[1],
			JobType:          f[2],
			RawState:         f[3],
			LastResult:       f[4],
			ScheduleEnabled:  strings.EqualFold(strings.TrimSpace(f[5]), "true"),
			LastRunStart:     f[6],
			LastRunEnd:       f[7],
			NextRun:          f[8],
			ProgressPercent:  int(atoi64(f[9])),
			ProcessedBytes:   atoi64(f[10]),
			TransferredBytes: atoi64(f[11]),
			DurationSeconds:  atoi64(f[12]),
			Repository:       f[13],
			Description:      f[14],
		})
	}
	return jobs, nil
}
