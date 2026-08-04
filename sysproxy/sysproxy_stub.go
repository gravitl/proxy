//go:build !darwin && !windows && !linux && !freebsd

package sysproxy

import "fmt"

func apply(pacPath string, opts Options) error {
	return fmt.Errorf("sysproxy: system PAC not supported on this platform")
}

func clear(opts Options) error {
	clearStateFile(opts)
	return nil
}
