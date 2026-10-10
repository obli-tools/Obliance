package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// readLinuxDMIRaw: /sys/class/dmi/id files -> raw.dmi, the keys Oblireach
// Desktop reads (sys_vendor, product_name, product_version|product_family,
// product_serial, chassis_type).
func TestReadLinuxDMIRaw(t *testing.T) {
	write := func(dir string, files map[string]string) {
		for k, v := range files {
			if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Lenovo laptop as the kernel shows it (values end with "\n"), read as root.
	dir := t.TempDir()
	write(dir, map[string]string{
		"sys_vendor":      "LENOVO\n",
		"product_name":    "21AH00BXFR\n",
		"product_version": "ThinkPad T14 Gen 3\n",
		"product_family":  "ThinkPad T14 Gen 3\n",
		"product_serial":  "PF3ABCDE\n",
		"chassis_type":    "10\n",
		"board_vendor":    "LENOVO\n", // not copied: the board has its own fields
	})
	want := map[string]interface{}{
		"sys_vendor": "LENOVO", "product_name": "21AH00BXFR", "product_version": "ThinkPad T14 Gen 3",
		"product_family": "ThinkPad T14 Gen 3", "product_serial": "PF3ABCDE", "chassis_type": "10",
	}
	if got := readLinuxDMIRaw(dir); !reflect.DeepEqual(got, want) {
		t.Errorf("lenovo: got %#v\nwant %#v", got, want)
	}

	// Dell server, product_serial unreadable (not root: here absent), blank
	// product_version -> left out.
	dir = t.TempDir()
	write(dir, map[string]string{
		"sys_vendor":      "Dell Inc.\n",
		"product_name":    "PowerEdge R640\n",
		"product_version": "   \n",
		"chassis_type":    "23\n",
	})
	want = map[string]interface{}{"sys_vendor": "Dell Inc.", "product_name": "PowerEdge R640", "chassis_type": "23"}
	if got := readLinuxDMIRaw(dir); !reflect.DeepEqual(got, want) {
		t.Errorf("dell: got %#v\nwant %#v", got, want)
	}

	// No DMI at all (ARM board, container): empty map (raw.dmi not set).
	if got := readLinuxDMIRaw(filepath.Join(t.TempDir(), "missing")); len(got) != 0 {
		t.Errorf("missing dir: got %#v", got)
	}
}
