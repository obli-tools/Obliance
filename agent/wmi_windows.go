//go:build windows
// +build windows

package main

// Native WMI access (COM, through go-ole) — no PowerShell process, no
// PowerShell version requirement. Used by the hardware inventory and the
// system-disk / SMBIOS identity readers so they behave the same from
// Windows 7 / Server 2008 R2 (PowerShell 2.0, no ConvertTo-Json) to
// Windows 11 / Server 2025 (where wmic.exe may be gone).
//
// One wmiSession = one OS-locked goroutine with COM initialised (MTA), one
// SWbemLocator and one SWbemServices per namespace, reused by every query of
// the session. Rows are returned as wmiRow maps (property name -> Go value
// from VARIANT.Value(); arrays as []interface{}; NULL / missing = absent key),
// converted by the platform-independent helpers of wmi_values.go.

import (
	"errors"
	"fmt"
	"runtime"
	"time"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

type wmiSession struct {
	unknown *ole.IUnknown
	locator *ole.IDispatch
	svcs    map[string]*ole.IDispatch
	svcVars []*ole.VARIANT
	uninit  bool
}

// errWMITimeout: the session function did not finish in time (a broken WMI
// repository can block COM calls indefinitely; the goroutine is abandoned).
var errWMITimeout = errors.New("wmi: timed out")

const (
	rpcEChangedMode           = 0x80010106 // COM already initialised as STA on this thread
	wbemFlagForwardOnly       = 0x20
	wbemFlagReturnImmediately = 0x10
)

// withWMI runs fn on a dedicated OS thread with COM initialised. It returns
// errWMITimeout if fn has not returned after timeout (fn keeps running in the
// background until its COM call returns; its result is then discarded).
func withWMI(timeout time.Duration, fn func(s *wmiSession) error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("wmi: panic: %v", r)
			}
		}()
		s, err := openWMISession()
		if err != nil {
			done <- err
			return
		}
		defer s.close()
		done <- fn(s)
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return errWMITimeout
	}
}

func openWMISession() (*wmiSession, error) {
	s := &wmiSession{svcs: map[string]*ole.IDispatch{}}
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		var oe *ole.OleError
		if errors.As(err, &oe) {
			switch uint32(oe.Code()) {
			case 0, 1: // S_OK, S_FALSE (already initialised, MTA): balance it
				s.uninit = true
			case rpcEChangedMode: // STA on this thread: usable, do not uninit
			default:
				return nil, fmt.Errorf("wmi: CoInitializeEx: %w", err)
			}
		} else {
			return nil, fmt.Errorf("wmi: CoInitializeEx: %w", err)
		}
	} else {
		s.uninit = true
	}
	unk, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil || unk == nil {
		s.close()
		if err == nil {
			err = errors.New("nil locator")
		}
		return nil, fmt.Errorf("wmi: SWbemLocator: %w", err)
	}
	s.unknown = unk
	loc, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		s.close()
		return nil, fmt.Errorf("wmi: locator IDispatch: %w", err)
	}
	s.locator = loc
	return s, nil
}

func (s *wmiSession) close() {
	for _, v := range s.svcVars {
		v.Clear()
	}
	s.svcVars = nil
	s.svcs = map[string]*ole.IDispatch{}
	if s.locator != nil {
		s.locator.Release()
		s.locator = nil
	}
	if s.unknown != nil {
		s.unknown.Release()
		s.unknown = nil
	}
	if s.uninit {
		ole.CoUninitialize()
		s.uninit = false
	}
}

// service returns the (cached) SWbemServices of a namespace ("" = root\cimv2).
func (s *wmiSession) service(namespace string) (*ole.IDispatch, error) {
	if namespace == "" {
		namespace = `root\cimv2`
	}
	if svc, ok := s.svcs[namespace]; ok {
		return svc, nil
	}
	v, err := oleutil.CallMethod(s.locator, "ConnectServer", nil, namespace)
	if err != nil {
		return nil, fmt.Errorf("wmi: connect %s: %w", namespace, err)
	}
	svc := v.ToIDispatch()
	if svc == nil {
		v.Clear()
		return nil, fmt.Errorf("wmi: connect %s: no service", namespace)
	}
	s.svcVars = append(s.svcVars, v)
	s.svcs[namespace] = svc
	return svc, nil
}

// query runs a WQL query and reads the listed properties of every result.
// A property the class does not have (older Windows) is simply absent from
// the row, like a NULL value.
func (s *wmiSession) query(namespace, wql string, props ...string) ([]wmiRow, error) {
	var rows []wmiRow
	err := s.forEachObject(namespace, wql, props, func(_ *ole.IDispatch, row wmiRow) error {
		rows = append(rows, row)
		return nil
	})
	if err != nil {
		// A forward-only enumeration that fails midway (e.g. invalid class /
		// property in the WQL surfaces here, not at ExecQuery) — keep nothing.
		return nil, err
	}
	return rows, nil
}

// forEachObject runs a WQL query and calls fn with every SWbemObject (valid
// only during the call) and its listed properties.
func (s *wmiSession) forEachObject(namespace, wql string, props []string, fn func(obj *ole.IDispatch, row wmiRow) error) error {
	svc, err := s.service(namespace)
	if err != nil {
		return err
	}
	resV, err := oleutil.CallMethod(svc, "ExecQuery", wql, "WQL", wbemFlagForwardOnly|wbemFlagReturnImmediately)
	if err != nil {
		return fmt.Errorf("wmi: %s: %w", wql, err)
	}
	defer resV.Clear()
	res := resV.ToIDispatch()
	if res == nil {
		return fmt.Errorf("wmi: %s: no result set", wql)
	}
	return oleutil.ForEach(res, func(item *ole.VARIANT) error {
		defer item.Clear()
		obj := item.ToIDispatch()
		if obj == nil {
			return nil
		}
		row := wmiRow{}
		for _, p := range props {
			pv, err := oleutil.GetProperty(obj, p)
			if err != nil {
				continue
			}
			if val, ok := variantValue(pv); ok {
				row[p] = val
			}
			pv.Clear()
		}
		return fn(obj, row)
	})
}

// execMethod calls a WMI method on an instance (SWbemObject.ExecMethod_ with
// an InParameters instance holding args) and returns the listed out
// parameters (ReturnValue is always read).
func execMethod(obj *ole.IDispatch, method string, args map[string]interface{}, outProps ...string) (wmiRow, error) {
	methodsV, err := oleutil.GetProperty(obj, "Methods_")
	if err != nil {
		return nil, fmt.Errorf("wmi: Methods_: %w", err)
	}
	defer methodsV.Clear()
	mV, err := oleutil.CallMethod(methodsV.ToIDispatch(), "Item", method)
	if err != nil {
		return nil, fmt.Errorf("wmi: method %s: %w", method, err)
	}
	defer mV.Clear()
	var inst *ole.IDispatch
	if len(args) > 0 {
		inClassV, err := oleutil.GetProperty(mV.ToIDispatch(), "InParameters")
		if err != nil {
			return nil, fmt.Errorf("wmi: %s InParameters: %w", method, err)
		}
		defer inClassV.Clear()
		instV, err := oleutil.CallMethod(inClassV.ToIDispatch(), "SpawnInstance_")
		if err != nil {
			return nil, fmt.Errorf("wmi: %s SpawnInstance_: %w", method, err)
		}
		defer instV.Clear()
		inst = instV.ToIDispatch()
		for k, v := range args {
			pv, err := oleutil.PutProperty(inst, k, v)
			if err != nil {
				return nil, fmt.Errorf("wmi: %s.%s: %w", method, k, err)
			}
			if pv != nil {
				pv.Clear()
			}
		}
	}
	var outV *ole.VARIANT
	if inst != nil {
		outV, err = oleutil.CallMethod(obj, "ExecMethod_", method, inst)
	} else {
		outV, err = oleutil.CallMethod(obj, "ExecMethod_", method)
	}
	if err != nil {
		return nil, fmt.Errorf("wmi: %s: %w", method, err)
	}
	defer outV.Clear()
	out := wmiRow{}
	outObj := outV.ToIDispatch()
	if outObj == nil {
		return out, nil
	}
	for _, p := range append([]string{"ReturnValue"}, outProps...) {
		pv, err := oleutil.GetProperty(outObj, p)
		if err != nil {
			continue
		}
		if val, ok := variantValue(pv); ok {
			out[p] = val
		}
		pv.Clear()
	}
	return out, nil
}

// variantValue converts a property VARIANT; ok=false for NULL / EMPTY.
func variantValue(v *ole.VARIANT) (interface{}, bool) {
	if v == nil || v.VT == ole.VT_NULL || v.VT == ole.VT_EMPTY {
		return nil, false
	}
	if v.VT&ole.VT_ARRAY != 0 {
		arr := v.ToArray()
		if arr == nil {
			return nil, false
		}
		return arr.ToValueArray(), true
	}
	return v.Value(), true
}
