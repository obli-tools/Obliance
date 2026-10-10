//go:build windows

package main

import (
	"testing"
)

// TestVeeamEnumScriptWithFakeJobs runs the REAL enumeration script on this
// machine with Get-VBRJob / Get-VBRComputerBackupJob replaced by fakes (PSObject
// + ScriptMethods, PowerShell 2.0-compatible constructs) and checks the
// VJOB lines decode into the expected jobs: null fields, "|" and non-ASCII in
// names, a job without session, a failing Get-VBRComputerBackupJob.
func TestVeeamEnumScriptWithFakeJobs(t *testing.T) {
	const fakes = `
function New-FakeJob($id, $name, $state, $result, $sched, $withSession) {
  $j = New-Object PSObject
  $j | Add-Member NoteProperty Id $id
  $j | Add-Member NoteProperty Name $name
  $j | Add-Member NoteProperty JobType 'Backup'
  $j | Add-Member NoteProperty IsScheduleEnabled $sched
  $j | Add-Member NoteProperty Description $null
  $j | Add-Member ScriptMethod GetLastResult ([scriptblock]::Create("'" + $result + "'"))
  $j | Add-Member ScriptMethod GetLastState ([scriptblock]::Create("'" + $state + "'"))
  if ($withSession) {
    $j | Add-Member ScriptMethod FindLastSession {
      $p = New-Object PSObject
      $p | Add-Member NoteProperty Percents 100
      $p | Add-Member NoteProperty ProcessedSize ([int64]5368709120)
      $p | Add-Member NoteProperty TransferedSize ([int64]1073741824)
      $s = New-Object PSObject
      $s | Add-Member NoteProperty CreationTime ([datetime]'2026-09-30T22:00:00Z')
      $s | Add-Member NoteProperty EndTime ([datetime]'2026-09-30T23:00:00Z')
      $s | Add-Member NoteProperty Progress $p
      $s
    }
  } else {
    $j | Add-Member ScriptMethod FindLastSession { $null }
  }
  $j | Add-Member ScriptMethod GetTargetRepository { throw 'no repo' }
  $j
}
function Get-VBRJob { New-FakeJob 'id-1' ('Nightly | DC01 ' + [char]0x00E9) 'Stopped' 'Success' $true $true; New-FakeJob 'id-2' 'Copy' 'Working' 'None' $false $false }
function Get-VBRComputerBackupJob { throw 'not on this version' }
`
	out, err := runPS(fakes + enumJobsScript)
	if err != nil {
		t.Skipf("powershell unavailable: %v (%s)", err, out)
	}
	raw, err := parseVeeamJobLines(string(out))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if len(raw) != 2 {
		t.Fatalf("jobs = %+v\noutput:\n%s", raw, out)
	}
	a, b := raw[0], raw[1]
	if a.JobID != "id-1" || a.Name != "Nightly | DC01 é" || a.RawState != "Stopped" || a.LastResult != "Success" || !a.ScheduleEnabled ||
		a.ProgressPercent != 100 || a.ProcessedBytes != 5368709120 || a.TransferredBytes != 1073741824 || a.DurationSeconds != 3600 ||
		a.Repository != "" || a.Description != "" || a.LastRunStart == "" || a.LastRunEnd == "" {
		t.Errorf("job 1 = %+v", a)
	}
	if b.JobID != "id-2" || b.RawState != "Working" || b.ScheduleEnabled || b.LastRunStart != "" || b.ProgressPercent != 0 {
		t.Errorf("job 2 = %+v", b)
	}
	if normaliseJobState(b.RawState, b.ScheduleEnabled) != "running" || normaliseJobState(a.RawState, a.ScheduleEnabled) != "idle" {
		t.Errorf("states")
	}
}
