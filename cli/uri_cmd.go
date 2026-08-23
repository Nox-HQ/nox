package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nox-hq/nox/plugin"
)

// runURI dispatches `nox uri` subcommands. Two surfaces today:
//
//	nox uri <uri>             — handle a nox:// URI (install action)
//	nox uri register          — print or apply OS-level URL handler
//
// Marketplace pages and docs use `nox://install?plugin=nox/ai-eval`
// links so an operator can click and have nox install the plugin
// without copy-pasting a shell command. The OS dispatches the URI
// to the running nox binary; we parse and route to plugin install.
func runURI(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox uri <uri> | register | unregister")
		return 2
	}

	switch args[0] {
	case "register":
		return runURIRegister(args[1:])
	case "unregister":
		return runURIUnregister(args[1:])
	default:
		return runURIDispatch(args[0])
	}
}

// runURIDispatch parses raw and runs the action it encodes.
func runURIDispatch(raw string) int {
	if !strings.HasPrefix(raw, "nox://") {
		fmt.Fprintf(os.Stderr, "error: expected nox:// URI, got %q\n", raw)
		return 2
	}

	u, err := url.Parse(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing %q: %v\n", raw, err)
		return 2
	}

	switch u.Host {
	case "install":
		return uriDispatchInstall(u)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown nox:// action %q (supported: install)\n", u.Host)
		return 2
	}
}

// uriDispatchInstall handles `nox://install?plugin=NAME[&version=V]`.
// Reuses the same install machinery as the CLI subcommand so the
// behaviour is identical regardless of entrypoint.
func uriDispatchInstall(u *url.URL) int {
	q := u.Query()
	name := q.Get("plugin")
	if name == "" {
		fmt.Fprintln(os.Stderr, "error: nox://install requires ?plugin=NAME")
		return 2
	}
	if !plugin.IsSafeName(name) {
		fmt.Fprintln(os.Stderr, "error: invalid plugin name in URI")
		return 2
	}
	version := q.Get("version")
	spec := name
	if version != "" {
		if !plugin.IsSafeVersionConstraint(version) {
			fmt.Fprintln(os.Stderr, "error: invalid version in URI")
			return 2
		}
		spec = name + "@" + version
	}

	fmt.Printf("nox uri: installing %s\n", spec)
	return runPluginInstall([]string{spec})
}

// runURIRegister installs the OS-level URL scheme handler that
// dispatches `nox://` clicks back to the running binary. macOS
// requires an .app bundle so we generate a minimal one; Linux
// writes a .desktop file and refreshes the mime cache; Windows
// emits a .reg snippet the operator runs once.
func runURIRegister(args []string) int {
	fs := flag.NewFlagSet("uri register", flag.ContinueOnError)
	var dryRun bool
	fs.BoolVar(&dryRun, "dry-run", false, "print the registration without applying it")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: locating nox binary: %v\n", err)
		return 2
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	switch runtime.GOOS {
	case "linux":
		return registerLinux(exe, dryRun)
	case "darwin":
		return registerDarwin(exe, dryRun)
	case "windows":
		return registerWindows(exe, dryRun)
	default:
		fmt.Fprintf(os.Stderr, "error: nox uri register not supported on %s\n", runtime.GOOS)
		return 2
	}
}

func runURIUnregister(args []string) int {
	switch runtime.GOOS {
	case "linux":
		path := filepath.Join(linuxAppsDir(), "nox-uri.desktop")
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error: removing %s: %v\n", path, err)
			return 2
		}
		_ = exec.Command("update-desktop-database", linuxAppsDir()).Run()
		fmt.Printf("Removed %s\n", path)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Unregister currently supported only on linux. Reverse the steps printed by `nox uri register --dry-run`.\n")
		return 2
	}
}

// ---- linux ---------------------------------------------------------

func linuxAppsDir() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "applications")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "applications")
}

func registerLinux(exe string, dryRun bool) int {
	dest := filepath.Join(linuxAppsDir(), "nox-uri.desktop")
	body := fmt.Sprintf(`[Desktop Entry]
Name=Nox URI Handler
Exec=%s uri %%u
Type=Application
Terminal=false
NoDisplay=true
MimeType=x-scheme-handler/nox;
`, exe)

	if dryRun {
		fmt.Printf("# Would write %s:\n%s", dest, body)
		fmt.Println("# Then run: update-desktop-database " + linuxAppsDir())
		return 0
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: creating %s: %v\n", filepath.Dir(dest), err)
		return 2
	}
	if err := os.WriteFile(dest, []byte(body), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", dest, err)
		return 2
	}
	if err := exec.Command("update-desktop-database", linuxAppsDir()).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "warn: update-desktop-database failed (you may need to log out / log in): %v\n", err)
	}
	fmt.Printf("Registered nox:// → %s\n", exe)
	fmt.Printf("Test with: xdg-open 'nox://install?plugin=nox/ai-eval'\n")
	return 0
}

// ---- darwin --------------------------------------------------------

func registerDarwin(exe string, dryRun bool) int {
	// macOS requires a real .app bundle for URL scheme registration.
	// Build a minimal one in ~/Applications/ with Info.plist that
	// declares the nox:// scheme and a wrapper shell script that
	// forwards the URI to the binary.
	home, _ := os.UserHomeDir()
	appPath := filepath.Join(home, "Applications", "NoxURIHandler.app")
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>dev.nox.uri-handler</string>
  <key>CFBundleName</key><string>Nox URI Handler</string>
  <key>CFBundleExecutable</key><string>nox-uri</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>LSUIElement</key><true/>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLName</key><string>Nox Plugin Install</string>
      <key>CFBundleURLSchemes</key>
      <array><string>nox</string></array>
    </dict>
  </array>
</dict>
</plist>
`
	wrapper := fmt.Sprintf(`#!/bin/sh
exec %q uri "$1"
`, exe)

	if dryRun {
		fmt.Printf("# Would create %s/Contents/Info.plist:\n%s\n", appPath, plist)
		fmt.Printf("# Would create %s/Contents/MacOS/nox-uri:\n%s\n", appPath, wrapper)
		fmt.Println("# Then run: /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f " + appPath)
		return 0
	}

	contents := filepath.Join(appPath, "Contents")
	macos := filepath.Join(contents, "MacOS")
	if err := os.MkdirAll(macos, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if err := os.WriteFile(filepath.Join(contents, "Info.plist"), []byte(plist), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	wrapperPath := filepath.Join(macos, "nox-uri")
	if err := os.WriteFile(wrapperPath, []byte(wrapper), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	lsregister := "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
	if _, err := os.Stat(lsregister); err == nil {
		_ = exec.Command(lsregister, "-f", appPath).Run()
	}
	fmt.Printf("Registered nox:// via %s\n", appPath)
	fmt.Printf("Test with: open 'nox://install?plugin=nox/ai-eval'\n")
	return 0
}

// ---- windows -------------------------------------------------------

func registerWindows(exe string, dryRun bool) int {
	reg := fmt.Sprintf(`Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Classes\nox]
@="URL:Nox Plugin Install"
"URL Protocol"=""

[HKEY_CURRENT_USER\Software\Classes\nox\DefaultIcon]
@="%s,1"

[HKEY_CURRENT_USER\Software\Classes\nox\shell]

[HKEY_CURRENT_USER\Software\Classes\nox\shell\open]

[HKEY_CURRENT_USER\Software\Classes\nox\shell\open\command]
@="\"%s\" uri \"%%1\""
`, strings.ReplaceAll(exe, `\`, `\\`), strings.ReplaceAll(exe, `\`, `\\`))

	if dryRun {
		fmt.Print(reg)
		return 0
	}

	tmp, err := os.CreateTemp("", "nox-uri-*.reg")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // best-effort
	if _, err := tmp.WriteString(reg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	tmp.Close() //nolint:errcheck // best-effort

	cmd := exec.Command("reg.exe", "import", tmp.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reg.exe import failed: %v\n%s\n", err, out)
		return 2
	}
	fmt.Printf("Registered nox:// in HKCU\\Software\\Classes\\nox\n")
	return 0
}
