//go:build windows

package sysproxy

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
	internetSettingsPath          = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
)

func apply(pacPath string, opts Options) error {
	pacURL := FileURL(pacPath)
	n, err := setAutoConfigURLAllUsers(pacURL)
	if err != nil && n == 0 {
		return err
	}
	notifyWinINET()
	saveState(opts, state{Applied: true, PACFileURL: pacURL})
	if n == 0 {
		return fmt.Errorf("sysproxy: no user hive accepted AutoConfigURL")
	}
	return nil
}

func clear(opts Options) error {
	st := loadState(opts)
	clearAutoConfigURLAllUsers(st.PACFileURL)
	notifyWinINET()
	clearStateFile(opts)
	return nil
}

func setAutoConfigURLAllUsers(pacURL string) (int, error) {
	var n int
	var lastErr error
	for _, root := range userInternetSettingsRoots() {
		k, err := registry.OpenKey(root.hive, root.path, registry.SET_VALUE)
		if err != nil {
			lastErr = err
			continue
		}
		if err := k.SetStringValue("AutoConfigURL", pacURL); err != nil {
			lastErr = err
			k.Close()
			continue
		}
		_ = k.SetDWordValue("ProxyEnable", 0)
		k.Close()
		n++
	}
	return n, lastErr
}

func clearAutoConfigURLAllUsers(ownedURL string) {
	for _, root := range userInternetSettingsRoots() {
		k, err := registry.OpenKey(root.hive, root.path, registry.SET_VALUE|registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		cur, _, _ := k.GetStringValue("AutoConfigURL")
		if ownedURL != "" && cur != ownedURL && !strings.Contains(strings.ToLower(cur), "egress_proxy.pac") {
			k.Close()
			continue
		}
		_ = k.DeleteValue("AutoConfigURL")
		k.Close()
	}
}

type regRoot struct {
	hive registry.Key
	path string
}

func userInternetSettingsRoots() []regRoot {
	roots := []regRoot{{hive: registry.CURRENT_USER, path: internetSettingsPath}}

	users, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return roots
	}
	defer users.Close()
	names, err := users.ReadSubKeyNames(-1)
	if err != nil {
		return roots
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "S-1-5-21-") || strings.HasSuffix(name, "_Classes") {
			continue
		}
		roots = append(roots, regRoot{
			hive: registry.USERS,
			path: name + `\` + internetSettingsPath,
		})
	}
	return roots
}

func notifyWinINET() {
	wininet := windows.NewLazySystemDLL("wininet.dll")
	internetSetOptionW := wininet.NewProc("InternetSetOptionW")
	if internetSetOptionW.Find() != nil {
		return
	}
	_, _, _ = internetSetOptionW.Call(0, uintptr(internetOptionSettingsChanged), 0, 0)
	_, _, _ = internetSetOptionW.Call(0, uintptr(internetOptionRefresh), 0, 0)
}
