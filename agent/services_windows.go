//go:build windows

package main

// Native Windows service management through the Service Control Manager
// (golang.org/x/sys/windows + svc/mgr) instead of PowerShell: works the same
// on every Windows (PowerShell 2.0 on Windows 7 / 2008 R2 has neither
// Get-CimInstance nor ConvertTo-Json, and Get-Service has no StartType before
// PowerShell 5), and costs no powershell.exe spawn.
//
// The result shapes are those the PowerShell implementation produced, so the
// server and the web UI need no change:
//   - list_services: ServiceInfo{name, displayName, status, startType,
//     runAsUser} with the Win32_Service strings lower-cased
//     (status "running" / "stopped" / "start pending" / ..., startType "auto"
//     / "auto_delayed" (4.5.103+) / "manual" / "disabled" / "boot" /
//     "system").
//   - set_service_start_type: {"name", "startType", "status"} read back
//     (service_start_type.go).
//   - start/stop/restart_service: {"name": ..., "output": <the former
//     `Select-Object Name,Status | ConvertTo-Json -Compress`>}, i.e.
//     {"Name":"Spooler","Status":4} (Status = ServiceControllerStatus, whose
//     numeric values are the SERVICE_* state codes).

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	svcControlTimeout = 60 * time.Second
	svcPollInterval   = 250 * time.Millisecond
)

// win32ServiceStateName maps a SERVICE_* state code to the Win32_Service
// "State" string.
func win32ServiceStateName(state uint32) string {
	switch state {
	case windows.SERVICE_STOPPED:
		return "Stopped"
	case windows.SERVICE_START_PENDING:
		return "Start Pending"
	case windows.SERVICE_STOP_PENDING:
		return "Stop Pending"
	case windows.SERVICE_RUNNING:
		return "Running"
	case windows.SERVICE_CONTINUE_PENDING:
		return "Continue Pending"
	case windows.SERVICE_PAUSE_PENDING:
		return "Pause Pending"
	case windows.SERVICE_PAUSED:
		return "Paused"
	}
	return "Unknown"
}

// win32ServiceStartModeName maps a SERVICE_*_START code to the Win32_Service
// "StartMode" string.
func win32ServiceStartModeName(startType uint32) string {
	switch startType {
	case windows.SERVICE_BOOT_START:
		return "Boot"
	case windows.SERVICE_SYSTEM_START:
		return "System"
	case windows.SERVICE_AUTO_START:
		return "Auto"
	case windows.SERVICE_DEMAND_START:
		return "Manual"
	case windows.SERVICE_DISABLED:
		return "Disabled"
	}
	return "Unknown"
}

// psServiceStartTypeName maps a start type to Get-Service's StartType
// (System.ServiceProcess.ServiceStartMode) name.
func psServiceStartTypeName(startType uint32) string {
	switch startType {
	case windows.SERVICE_BOOT_START:
		return "Boot"
	case windows.SERVICE_SYSTEM_START:
		return "System"
	case windows.SERVICE_AUTO_START:
		return "Automatic"
	case windows.SERVICE_DEMAND_START:
		return "Manual"
	case windows.SERVICE_DISABLED:
		return "Disabled"
	}
	return ""
}

// psServiceStatusName maps a state to Get-Service's Status
// (System.ServiceProcess.ServiceControllerStatus) name.
func psServiceStatusName(state uint32) string {
	switch state {
	case windows.SERVICE_STOPPED:
		return "Stopped"
	case windows.SERVICE_START_PENDING:
		return "StartPending"
	case windows.SERVICE_STOP_PENDING:
		return "StopPending"
	case windows.SERVICE_RUNNING:
		return "Running"
	case windows.SERVICE_CONTINUE_PENDING:
		return "ContinuePending"
	case windows.SERVICE_PAUSE_PENDING:
		return "PausePending"
	case windows.SERVICE_PAUSED:
		return "Paused"
	}
	return ""
}

// serviceControlOutput is the JSON the PowerShell `-PassThru | Select-Object
// Name,Status | ConvertTo-Json -Compress` pipeline printed.
func serviceControlOutput(name string, state uint32) string {
	b, _ := json.Marshal(struct {
		Name   string `json:"Name"`
		Status uint32 `json:"Status"`
	}{name, state})
	return string(b)
}

// openSCM opens the SCM with only the rights needed (mgr.Connect asks for
// SC_MANAGER_ALL_ACCESS, which a non-elevated caller does not get).
func openSCM(access uint32) (*mgr.Mgr, error) {
	h, err := windows.OpenSCManager(nil, nil, access)
	if err != nil {
		return nil, err
	}
	return &mgr.Mgr{Handle: h}, nil
}

// listServicesNative enumerates every Win32 service (what Win32_Service
// returns) with its state, start mode and run-as account.
func listServicesNative() ([]ServiceInfo, error) {
	m, err := openSCM(windows.SC_MANAGER_CONNECT | windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, fmt.Errorf("open service manager: %w", err)
	}
	defer m.Disconnect()

	var needed, count, resume uint32
	buf := make([]byte, 64*1024)
	var services []ServiceInfo
	for {
		err := windows.EnumServicesStatusEx(m.Handle, windows.SC_ENUM_PROCESS_INFO,
			windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
			&buf[0], uint32(len(buf)), &needed, &count, &resume, nil)
		if err != nil && err != windows.ERROR_MORE_DATA {
			return nil, fmt.Errorf("enumerate services: %w", err)
		}
		if count > 0 {
			entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count)
			for _, e := range entries {
				name := windows.UTF16PtrToString(e.ServiceName)
				si := ServiceInfo{
					Name:        name,
					DisplayName: windows.UTF16PtrToString(e.DisplayName),
					Status:      strings.ToLower(win32ServiceStateName(e.ServiceStatusProcess.CurrentState)),
				}
				if startType, delayed, account, ok := queryServiceStartConfig(m, name); ok {
					si.StartType = listStartTypeName(startType, delayed)
					si.RunAsUser = account
				}
				services = append(services, si)
			}
		}
		if err == nil {
			break
		}
		// ERROR_MORE_DATA: grow when even one entry did not fit, then continue
		// from the resume handle.
		if count == 0 {
			if needed <= uint32(len(buf)) || needed > 16<<20 {
				return nil, fmt.Errorf("enumerate services: unexpected buffer size %d", needed)
			}
			buf = make([]byte, needed)
		}
	}
	if services == nil {
		services = []ServiceInfo{}
	}
	return services, nil
}

// queryServiceStartConfig reads a service's start type (+ the delayed
// auto-start flag of an automatic service) and run-as account.
func queryServiceStartConfig(m *mgr.Mgr, name string) (startType uint32, delayed bool, account string, ok bool) {
	n16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, false, "", false
	}
	h, err := windows.OpenService(m.Handle, n16, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return 0, false, "", false
	}
	defer windows.CloseServiceHandle(h)
	startType, account, ok = queryServiceConfigBasic(h)
	if ok && startType == windows.SERVICE_AUTO_START {
		delayed = queryDelayedAutoStart(h)
	}
	return startType, delayed, account, ok
}

// queryServiceConfigBasic is QueryServiceConfig only (mgr.Service.Config also
// queries the description, delayed-start and SID-type infos, and fails as a
// whole when any of them does).
func queryServiceConfigBasic(h windows.Handle) (startType uint32, account string, ok bool) {
	n := uint32(1024)
	for i := 0; i < 4; i++ {
		buf := make([]uint64, (n+7)/8)
		cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
		err := windows.QueryServiceConfig(h, cfg, uint32(len(buf)*8), &n)
		if err == nil {
			return cfg.StartType, windows.UTF16PtrToString(cfg.ServiceStartName), true
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER || n == 0 || n > 64*1024 {
			return 0, "", false
		}
	}
	return 0, "", false
}

// openServiceFor opens one service with the given rights.
func openServiceFor(m *mgr.Mgr, name string, access uint32) (*mgr.Service, error) {
	n16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.OpenService(m.Handle, n16, access)
	if err != nil {
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return nil, fmt.Errorf("Cannot find any service with service name '%s'", name)
		}
		return nil, fmt.Errorf("open service '%s': %w", name, err)
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}

// waitServiceState polls until the service reaches want (or a terminal
// opposite state / the deadline).
func waitServiceState(s *mgr.Service, want svc.State, timeout time.Duration) (svc.State, error) {
	deadline := time.Now().Add(timeout)
	for {
		st, err := s.Query()
		if err != nil {
			return 0, err
		}
		if st.State == want {
			return st.State, nil
		}
		// Start requested but the service fell back to stopped: it failed.
		if want == svc.Running && st.State == svc.Stopped {
			return st.State, fmt.Errorf("service '%s' stopped while starting (exit code %d)", s.Name, st.Win32ExitCode)
		}
		if time.Now().After(deadline) {
			return st.State, fmt.Errorf("service '%s' did not reach the %s state within %s (state: %s)",
				s.Name, strings.ToLower(psServiceStatusName(uint32(want))), timeout, psServiceStatusName(uint32(st.State)))
		}
		time.Sleep(svcPollInterval)
	}
}

// startServiceNative = Start-Service: start (no-op when already running) and
// wait for RUNNING.
func startServiceNative(name string) (string, error) {
	m, err := openSCM(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", fmt.Errorf("open service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := openServiceFor(m, name, windows.SERVICE_START|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return "", err
	}
	defer s.Close()
	state, err := startAndWait(s)
	if err != nil {
		return "", err
	}
	return serviceControlOutput(name, uint32(state)), nil
}

func startAndWait(s *mgr.Service) (svc.State, error) {
	st, err := s.Query()
	if err != nil {
		return 0, err
	}
	if st.State == svc.Running {
		return st.State, nil
	}
	if st.State != svc.StartPending {
		if err := s.Start(); err != nil && err != windows.ERROR_SERVICE_ALREADY_RUNNING {
			return 0, fmt.Errorf("Service '%s' cannot be started: %w", s.Name, err)
		}
	}
	return waitServiceState(s, svc.Running, svcControlTimeout)
}

// stopServiceNative = Stop-Service -Force: stops the active dependent services
// first, then the service, waiting for STOPPED. Returns the dependents it
// stopped (in stop order).
func stopServiceNative(name string) (string, []string, error) {
	m, err := openSCM(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", nil, fmt.Errorf("open service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := openServiceFor(m, name,
		windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS|windows.SERVICE_ENUMERATE_DEPENDENTS)
	if err != nil {
		return "", nil, err
	}
	defer s.Close()

	// EnumDependentServices returns the dependents in reverse start order,
	// i.e. the order in which they must be stopped.
	deps, _ := s.ListDependentServices(svc.Active)
	var stopped []string
	for _, dep := range deps {
		ds, err := openServiceFor(m, dep, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
		if err != nil {
			return "", stopped, fmt.Errorf("stop dependent service '%s': %w", dep, err)
		}
		err = stopAndWait(ds)
		ds.Close()
		if err != nil {
			return "", stopped, fmt.Errorf("stop dependent service '%s': %w", dep, err)
		}
		stopped = append(stopped, dep)
	}
	if err := stopAndWait(s); err != nil {
		return "", stopped, err
	}
	return serviceControlOutput(name, windows.SERVICE_STOPPED), stopped, nil
}

func stopAndWait(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil && err != windows.ERROR_SERVICE_NOT_ACTIVE {
			return fmt.Errorf("Service '%s' cannot be stopped: %w", s.Name, err)
		}
	}
	_, err = waitServiceState(s, svc.Stopped, svcControlTimeout)
	return err
}

// restartServiceNative = Restart-Service -Force: stop (dependents first),
// start the service, then start again the dependents that were running.
func restartServiceNative(name string) (string, error) {
	_, deps, err := stopServiceNative(name)
	if err != nil {
		return "", err
	}
	out, err := startServiceNative(name)
	if err != nil {
		return "", err
	}
	// Dependents in reverse stop order = start order (best effort, like the
	// SCM would do on demand).
	for i := len(deps) - 1; i >= 0; i-- {
		_, _ = startServiceNative(deps[i])
	}
	return out, nil
}

// serviceStartTypeAndStatus returns Get-Service's "StartType|Status" pair
// ("Automatic|Running") or found=false when the service does not exist.
func serviceStartTypeAndStatus(name string) (startType, status string, found bool, err error) {
	m, err := openSCM(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", "", false, err
	}
	defer m.Disconnect()
	n16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", "", false, err
	}
	h, err := windows.OpenService(m.Handle, n16, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST || err == windows.ERROR_INVALID_NAME {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer s.Close()
	if st, _, ok := queryServiceConfigBasic(h); ok {
		startType = psServiceStartTypeName(st)
	}
	if st, qerr := s.Query(); qerr == nil {
		status = psServiceStatusName(uint32(st.State))
	}
	return startType, status, true, nil
}

// queryDelayedAutoStart reads the delayed auto-start flag of a service
// (false when it cannot be read).
func queryDelayedAutoStart(h windows.Handle) bool {
	var info windows.SERVICE_DELAYED_AUTO_START_INFO
	var needed uint32
	err := windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), &needed)
	return err == nil && info.IsDelayedAutoStartUp != 0
}

// listStartTypeName is the list_services start type of a Win32 service:
// win32ServiceStartModeName lower-cased, "auto_delayed" for an automatic
// service with the delayed flag.
func listStartTypeName(startType uint32, delayed bool) string {
	if startType == windows.SERVICE_AUTO_START && delayed {
		return svcStartAutoDelayed
	}
	return strings.ToLower(win32ServiceStartModeName(startType))
}

// scmStartType maps a set_service_start_type value to SERVICE_*_START and
// the delayed auto-start flag.
func scmStartType(startType string) (code uint32, delayed bool, err error) {
	switch startType {
	case svcStartAuto:
		return windows.SERVICE_AUTO_START, false, nil
	case svcStartAutoDelayed:
		return windows.SERVICE_AUTO_START, true, nil
	case svcStartManual:
		return windows.SERVICE_DEMAND_START, false, nil
	case svcStartDisabled:
		return windows.SERVICE_DISABLED, false, nil
	}
	return 0, false, fmt.Errorf("unknown start type %q", startType)
}

// setServiceStartTypeNative = Set-Service -StartupType (+ the delayed flag):
// changes the start type only (the service keeps running or stays stopped)
// and returns the start type and state read back (list_services words).
func setServiceStartTypeNative(name, startType string) (newType, status string, err error) {
	code, delayed, err := scmStartType(startType)
	if err != nil {
		return "", "", err
	}
	m, err := openSCM(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", "", fmt.Errorf("open service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := openServiceFor(m, name,
		windows.SERVICE_CHANGE_CONFIG|windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return "", "", err
	}
	defer s.Close()

	if cur, _, ok := queryServiceConfigBasic(s.Handle); ok && (cur == windows.SERVICE_BOOT_START || cur == windows.SERVICE_SYSTEM_START) {
		return "", "", fmt.Errorf("'%s' is a driver (%s start): its start type is not changed from here", name, strings.ToLower(win32ServiceStartModeName(cur)))
	}
	if err := windows.ChangeServiceConfig(s.Handle, windows.SERVICE_NO_CHANGE, code, windows.SERVICE_NO_CHANGE,
		nil, nil, nil, nil, nil, nil, nil); err != nil {
		return "", "", fmt.Errorf("change the start type of '%s': %w", name, err)
	}
	// The delayed flag only means something on an automatic service: set it
	// (or clear it) there; clearing it elsewhere is best effort so that a
	// later switch to "auto" does not come back delayed.
	info := windows.SERVICE_DELAYED_AUTO_START_INFO{}
	if delayed {
		info.IsDelayedAutoStartUp = 1
	}
	derr := windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, (*byte)(unsafe.Pointer(&info)))
	if derr != nil && code == windows.SERVICE_AUTO_START {
		return "", "", fmt.Errorf("set the delayed start flag of '%s': %w", name, derr)
	}

	st, _, ok := queryServiceConfigBasic(s.Handle)
	if !ok {
		return "", "", fmt.Errorf("read back the configuration of '%s'", name)
	}
	newType = listStartTypeName(st, queryDelayedAutoStart(s.Handle))
	if newType != startType {
		return "", "", fmt.Errorf("'%s' start type is %s after the change, not %s", name, newType, startType)
	}
	if q, qerr := s.Query(); qerr == nil {
		status = strings.ToLower(win32ServiceStateName(uint32(q.State)))
	}
	return newType, status, nil
}
