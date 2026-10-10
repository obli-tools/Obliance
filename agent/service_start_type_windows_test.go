//go:build windows

package main

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestScmStartTypeMapping(t *testing.T) {
	cases := []struct {
		in      string
		code    uint32
		delayed bool
	}{
		{"auto", windows.SERVICE_AUTO_START, false},
		{"auto_delayed", windows.SERVICE_AUTO_START, true},
		{"manual", windows.SERVICE_DEMAND_START, false},
		{"disabled", windows.SERVICE_DISABLED, false},
	}
	for _, c := range cases {
		code, delayed, err := scmStartType(c.in)
		if err != nil || code != c.code || delayed != c.delayed {
			t.Errorf("scmStartType(%q) = %d, %v, %v; want %d, %v", c.in, code, delayed, err, c.code, c.delayed)
		}
		// Round trip: what the list reports is what was requested.
		if got := listStartTypeName(code, delayed); got != c.in {
			t.Errorf("listStartTypeName(%d, %v) = %q, want %q", code, delayed, got, c.in)
		}
	}
	if _, _, err := scmStartType("boot"); err == nil {
		t.Errorf("scmStartType(boot) must fail")
	}
	// The delayed flag only counts on an automatic service.
	if got := listStartTypeName(windows.SERVICE_DEMAND_START, true); got != "manual" {
		t.Errorf("listStartTypeName(demand, delayed) = %q, want manual", got)
	}
}

// The protected-service refusal happens before any SCM access.
func TestSetServiceStartTypeRefusesAgentService(t *testing.T) {
	d := &CommandDispatcher{}
	for _, name := range []string{"OblianceAgent", "OblireachAgent"} {
		_, err := d.handleSetServiceStartType(AgentCommand{Type: "set_service_start_type",
			Payload: map[string]interface{}{"name": name, "startType": "disabled"}})
		if err == nil {
			t.Fatalf("%s: expected a refusal", name)
		}
	}
}
