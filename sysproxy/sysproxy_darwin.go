//go:build darwin

package sysproxy

import (
	"fmt"
	"os/exec"
	"strings"
)

func apply(pacPath string, opts Options) error {
	pacURL := FileURL(pacPath)
	services, err := listDarwinNetworkServices()
	if err != nil {
		return err
	}
	var applied []string
	for _, svc := range services {
		if err := exec.Command("networksetup", "-setautoproxyurl", svc, pacURL).Run(); err != nil {
			continue
		}
		if err := exec.Command("networksetup", "-setautoproxystate", svc, "on").Run(); err != nil {
			continue
		}
		applied = append(applied, svc)
	}
	if len(applied) == 0 {
		return fmt.Errorf("sysproxy: no network services accepted PAC URL")
	}
	saveState(opts, state{
		Applied:        true,
		PACFileURL:     pacURL,
		DarwinServices: applied,
	})
	return nil
}

func clear(opts Options) error {
	st := loadState(opts)
	services := st.DarwinServices
	if len(services) == 0 {
		var err error
		services, err = listDarwinNetworkServices()
		if err != nil {
			clearStateFile(opts)
			return err
		}
	}
	var lastErr error
	for _, svc := range services {
		if err := exec.Command("networksetup", "-setautoproxystate", svc, "off").Run(); err != nil {
			lastErr = err
		}
		_ = exec.Command("networksetup", "-setautoproxyurl", svc, "").Run()
	}
	clearStateFile(opts)
	return lastErr
}

func listDarwinNetworkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("networksetup list: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	var services []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "An asterisk (*) denotes") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services, nil
}
