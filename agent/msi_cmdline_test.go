package main

import "testing"

func TestMsiCommandLine(t *testing.T) {
	cases := []struct{ params, want string }{
		{"", `msiexec.exe /i "C:\t\p.msi" /quiet /norestart`},
		{"/quiet /norestart", `msiexec.exe /i "C:\t\p.msi" /quiet /norestart`},
		{"SERVERURL=`\"https://passly.example`\" APIKEY=`\"AB CD`\"", `msiexec.exe /i "C:\t\p.msi" SERVERURL="https://passly.example" APIKEY="AB CD" /quiet /norestart`},
		{`SERVERURL="https://x" /qn`, `msiexec.exe /i "C:\t\p.msi" SERVERURL="https://x" /qn /norestart`},
		{`/passive /forcerestart`, `msiexec.exe /i "C:\t\p.msi" /passive /forcerestart`},
		{`NOTE="a /q inside"`, `msiexec.exe /i "C:\t\p.msi" NOTE="a /q inside" /quiet /norestart`},
		{"A=1\r\n  B=2", `msiexec.exe /i "C:\t\p.msi" A=1 B=2 /quiet /norestart`},
	}
	for _, c := range cases {
		got, err := msiCommandLine("/i", `C:\t\p.msi`, c.params)
		if err != nil || got != c.want {
			t.Errorf("%q:\n got %q (%v)\nwant %q", c.params, got, err, c.want)
		}
	}
	if _, err := msiCommandLine("/i", `C:\a" /x evil`, ""); err == nil {
		t.Error("a quote in the path must be refused")
	}
}
