//go:build darwin

package main

// Local socket between the menu-bar tray (logged-in user) and this daemon
// (root). See internal/trayipc for the protocol and the authorization rule:
// a privacy change is accepted only from root or from the console user,
// identified by the kernel (LOCAL_PEERCRED), never by anything the client
// sends. privacy.json itself stays root-owned 0644 (0444 when locked).

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/obliance/agent/internal/trayipc"
	"golang.org/x/sys/unix"
)

const (
	trayIPCMaxConns = 8
	// xucredVersion is XUCRED_VERSION from <sys/ucred.h> (not exported by
	// x/sys/unix).
	xucredVersion = 0
)

type daemonPrivacyBackend struct{}

func (daemonPrivacyBackend) Privacy() (bool, bool) {
	return IsPrivacyMode(), IsPrivacyLocked()
}

func (daemonPrivacyBackend) SetPrivacy(enabled bool, peerUID uint32) error {
	log.Printf("tray-ipc: privacy mode -> %v requested by uid %d", enabled, peerUID)
	return SetPrivacyMode(enabled, "user")
}

// consoleUser returns the owner of /dev/console (root at the login window).
func consoleUser() trayipc.Console {
	info, err := os.Stat("/dev/console")
	if err != nil {
		return trayipc.Console{}
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return trayipc.Console{}
	}
	return trayipc.Console{UID: st.Uid, Known: true}
}

// peerUID returns the effective UID of the process at the other end of conn.
func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	if cred == nil || cred.Version != xucredVersion {
		return 0, errors.New("unexpected xucred version")
	}
	return cred.Uid, nil
}

// prepareSocketDir makes sure SocketDir is a real directory owned by root
// with mode 0755 (nobody else can create or swap the socket in it).
func prepareSocketDir() error {
	dir := trayipc.SocketDir
	info, err := os.Lstat(dir)
	if err == nil {
		st, _ := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || st == nil || st.Uid != 0 || info.Mode().Perm() != 0755 {
			if err := os.RemoveAll(dir); err != nil {
				return fmt.Errorf("remove unexpected %s: %w", dir, err)
			}
		} else {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Mkdir(dir, 0755); err != nil {
		return err
	}
	return os.Chmod(dir, 0755)
}

// startTrayIPC listens on the tray socket for the daemon's lifetime. Errors
// only disable the tray's privacy toggle; they are logged, never fatal.
func startTrayIPC() {
	if os.Geteuid() != 0 {
		log.Printf("tray-ipc: not running as root, local socket disabled")
		return
	}
	if err := prepareSocketDir(); err != nil {
		log.Printf("tray-ipc: %v", err)
		return
	}
	_ = os.Remove(trayipc.SocketPath) // stale socket from a previous run
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: trayipc.SocketPath, Net: "unix"})
	if err != nil {
		log.Printf("tray-ipc: listen %s: %v", trayipc.SocketPath, err)
		return
	}
	// Any local user may connect (status is public); set_privacy is
	// authorized on the peer credentials.
	if err := os.Chmod(trayipc.SocketPath, 0666); err != nil {
		log.Printf("tray-ipc: chmod socket: %v", err)
	}
	log.Printf("tray-ipc: listening on %s", trayipc.SocketPath)

	go func() {
		sem := make(chan struct{}, trayIPCMaxConns)
		for {
			conn, err := ln.AcceptUnix()
			if err != nil {
				log.Printf("tray-ipc: accept: %v", err)
				time.Sleep(time.Second)
				continue
			}
			select {
			case sem <- struct{}{}:
			default:
				conn.Close() // too many concurrent clients
				continue
			}
			go func(c *net.UnixConn) {
				defer func() { <-sem }()
				defer c.Close()
				// set_privacy may stop ObliReach (up to a few seconds).
				_ = c.SetDeadline(time.Now().Add(20 * time.Second))
				uid, err := peerUID(c)
				if err != nil {
					log.Printf("tray-ipc: peer credentials: %v", err)
					return
				}
				resp := trayipc.Serve(c, uid, consoleUser(), daemonPrivacyBackend{})
				if !resp.OK {
					log.Printf("tray-ipc: request from uid %d refused: %s", uid, resp.Error)
				}
			}(conn)
		}
	}()
}
