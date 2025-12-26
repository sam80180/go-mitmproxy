//go:build !windows

package main

import (
	"github.com/erikdubbelboer/gspt"
)

func setproctitle(s string) error {
	gspt.SetProcTitle(s)
	return nil
} // end setproctitle()
