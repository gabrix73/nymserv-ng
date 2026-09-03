//go:build linux

package main

import "golang.org/x/sys/unix"

// disableEcho turns off terminal echo so the registry passphrase is not
// displayed and does not end up in a scrollback buffer.
func disableEcho(fd int) (*unix.Termios, error) {
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	saved := *t

	t.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, t); err != nil {
		return nil, err
	}
	return &saved, nil
}

func restoreEcho(fd int, saved *unix.Termios) {
	if saved != nil {
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, saved)
	}
}
