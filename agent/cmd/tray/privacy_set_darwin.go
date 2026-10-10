//go:build darwin

package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/obliance/agent/internal/trayipc"
)

// setPrivacy asks the root daemon to change privacy mode through its local
// socket. privacy.json is root-owned on macOS; the daemon checks that this
// process belongs to the console user (kernel peer credentials) and that
// the state is not locked by an administrator.
func setPrivacy(enabled bool) error {
	// The daemon may need a few seconds to stop ObliReach.
	resp, err := trayipc.Call(trayipc.SocketPath,
		trayipc.Request{Op: trayipc.OpSetPrivacy, Enabled: enabled}, 20*time.Second)
	if err != nil {
		return fmt.Errorf("the Obliance agent is not reachable (%v)", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			return errors.New("refused by the Obliance agent")
		}
		return errors.New(resp.Error)
	}
	return nil
}
