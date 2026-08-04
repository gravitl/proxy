//go:build linux || freebsd

package sysproxy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func apply(pacPath string, opts Options) error {
	pacURL := FileURL(pacPath)
	var errs []string

	if err := exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "auto").Run(); err == nil {
		_ = exec.Command("gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", pacURL).Run()
	} else {
		errs = append(errs, "gsettings unavailable")
	}

	if err := writeProfileDropIn(opts); err != nil {
		errs = append(errs, err.Error())
	}

	saveState(opts, state{Applied: true, PACFileURL: pacURL})
	if len(errs) == 2 {
		return fmt.Errorf("sysproxy: %s", strings.Join(errs, "; "))
	}
	return nil
}

func clear(opts Options) error {
	_ = exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
	_ = exec.Command("gsettings", "reset", "org.gnome.system.proxy", "autoconfig-url").Run()
	_ = removeProfileDropIn(opts)
	clearStateFile(opts)
	return nil
}

func writeProfileDropIn(opts Options) error {
	proxyURL := opts.LocalProxyURL
	if proxyURL == "" {
		return fmt.Errorf("LocalProxyURL required for profile drop-in")
	}
	name := opts.profileScriptName()
	content := fmt.Sprintf(`# Managed by github.com/gravitl/proxy/sysproxy — do not edit
export HTTPS_PROXY=%s
export HTTP_PROXY=%s
export https_proxy=%s
export http_proxy=%s
`, proxyURL, proxyURL, proxyURL, proxyURL)

	local := filepath.Join(opts.StateDir, name)
	if err := os.WriteFile(local, []byte(content), 0644); err != nil {
		return err
	}

	etc := "/etc/profile.d/" + name
	if err := os.WriteFile(etc, []byte(content), 0644); err != nil {
		return nil // StateDir copy is enough when /etc is not writable
	}
	return nil
}

func removeProfileDropIn(opts Options) error {
	name := opts.profileScriptName()
	if opts.StateDir != "" {
		_ = os.Remove(filepath.Join(opts.StateDir, name))
	}
	_ = os.Remove("/etc/profile.d/" + name)
	return nil
}
