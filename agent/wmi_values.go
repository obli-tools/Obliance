package main

// Platform-independent helpers that read the values of a native WMI row
// (wmi_windows.go). Kept free of COM so the inventory builders that use them
// are unit-tested on every OS with recorded rows.
//
// VARIANT typing notes (SWbemObject properties, as go-ole decodes them):
//   - CIM uint64 / sint64 (Capacity, Size, TotalVisibleMemorySize) arrive as
//     strings (VT_BSTR);
//   - CIM uint32 arrives as int32 (VT_I4): values >= 2^31 come out negative
//     (AdapterRAM of a 2-4 GB card) -> wmiUint32 reinterprets them;
//   - CIM uint16 / uint8 arrive as int32 / uint8;
//   - CIM datetime arrives as its DMTF string ("20250925000000.000000+000"),
//     the same text Get-WmiObject exposed.

import (
	"fmt"
	"strconv"
	"strings"
)

// wmiRow: one WMI object, property name -> value (NULL / missing = no key).
type wmiRow map[string]interface{}

// str returns the property as a string ("" when absent). Numbers are printed
// in decimal, like PowerShell's string conversion.
func (r wmiRow) str(name string) string {
	v, ok := r[name]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	}
	return fmt.Sprintf("%v", v)
}

// has reports whether the property is present and not NULL.
func (r wmiRow) has(name string) bool {
	v, ok := r[name]
	return ok && v != nil
}

// int64v returns the property as an int64 (0 when absent / not numeric).
// Strings are parsed (CIM 64-bit integers are strings).
func (r wmiRow) int64v(name string) int64 {
	v, ok := r[name]
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case int8:
		return int64(t)
	case int16:
		return int64(t)
	case int32:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case uint8:
		return int64(t)
	case uint16:
		return int64(t)
	case uint32:
		return int64(t)
	case uint64:
		return int64(t)
	case uint:
		return int64(t)
	case float32:
		return int64(t)
	case float64:
		return int64(t)
	case bool:
		if t {
			return 1
		}
		return 0
	case string:
		s := strings.TrimSpace(t)
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n
		}
		if n, err := strconv.ParseUint(s, 10, 64); err == nil {
			return int64(n)
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return int64(f)
		}
	}
	return 0
}

// uint32v reads a CIM uint32 property: a negative int32 (VT_I4 carrying a
// value >= 2^31) is reinterpreted as the unsigned value WMI meant.
func (r wmiRow) uint32v(name string) int64 {
	if v, ok := r[name].(int32); ok {
		return int64(uint32(v))
	}
	n := r.int64v(name)
	if n < 0 && n >= -1<<31 {
		return int64(uint32(int32(n)))
	}
	return n
}

// float64v returns the property as a float64 (0 when absent / not numeric).
func (r wmiRow) float64v(name string) float64 {
	v, ok := r[name]
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case float32:
		return float64(t)
	case float64:
		return t
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f
	}
	return float64(r.int64v(name))
}

// boolv: PowerShell's [bool] cast of the property (absent / NULL = false,
// non-zero number = true, non-empty string = true).
func (r wmiRow) boolv(name string) bool {
	v, ok := r[name]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != ""
	}
	return r.int64v(name) != 0
}

// strs returns a string-array property (IPAddress...) without empty items; a
// scalar string becomes a one-element slice.
func (r wmiRow) strs(name string) []string {
	v, ok := r[name]
	if !ok || v == nil {
		return nil
	}
	var out []string
	switch t := v.(type) {
	case []interface{}:
		for _, e := range t {
			if e == nil {
				continue
			}
			s := fmt.Sprintf("%v", e)
			if s != "" {
				out = append(out, s)
			}
		}
	case []string:
		for _, s := range t {
			if s != "" {
				out = append(out, s)
			}
		}
	case string:
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}
