package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/nox-hq/nox/core/fsutil"
)

const installCIUsage = `nox install-ci — write a GitHub Actions workflow that keeps watching

Usage:
  nox install-ci [flags]

Writes .github/workflows/nox.yml: a scan on every pull request and push, and a
scheduled run that notices advisories disclosed after the code was merged. What
the scheduled run does about a new advisory is the advisories block in
.nox.yaml; with none it reports and nothing else.

Flags:
  --dir        repository root (default ".")
  --branch     branch whose pushes are scanned (default "main")
  --cron       schedule for the advisory run (default "17 5 * * *", daily)
  --nox-ref    ref of nox-hq/nox the workflow uses (default: this release's commit SHA,
               labelled with its version; a tag is accepted but warned about)
  --nox-version  nox version the action installs (default: this release)
  --force      overwrite an existing workflow
  --print      write the workflow to stdout instead of a file
`

var (
	ciSafeValue = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	fullSHA     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	ciCronShape = regexp.MustCompile(`^[0-9*/,\-A-Za-z?#]+( [0-9*/,\-A-Za-z?#]+){4}$`)
)

type installCIData struct {
	Branch     string
	Cron       string
	NoxRef     string
	NoxLabel   string // trailing comment naming the release a SHA pins, e.g. " # v1.52.0"
	NoxVersion string
	Warning    string // printed to stderr; the workflow is still written
}

func runInstallCI(args []string) int {
	fs := flag.NewFlagSet("install-ci", flag.ContinueOnError)
	dir := fs.String("dir", ".", "repository root")
	branch := fs.String("branch", "main", "branch whose pushes are scanned")
	cron := fs.String("cron", "17 5 * * *", "schedule for the advisory run")
	ref := fs.String("nox-ref", "", "ref of nox-hq/nox the workflow uses")
	noxVersion := fs.String("nox-version", "", "nox version the action installs")
	force := fs.Bool("force", false, "overwrite an existing workflow")
	printOnly := fs.Bool("print", false, "write the workflow to stdout")
	fs.Usage = func() { fmt.Fprint(os.Stderr, installCIUsage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}

	data, err := resolveInstallCI(*branch, *cron, *ref, *noxVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if data.Warning != "" {
		fmt.Fprintf(os.Stderr, "warning: %s\n", data.Warning)
	}
	out, err := renderInstallCI(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if *printOnly {
		fmt.Print(out)
		return 0
	}

	path := filepath.Join(*dir, ".github", "workflows", "nox.yml")
	if _, err := os.Stat(path); err == nil && !*force {
		fmt.Fprintf(os.Stderr, "error: %s already exists; pass --force to overwrite\n", path)
		return 2
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // workflow directories are world-readable
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if err := fsutil.AtomicWriteFile(path, []byte(out), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	fmt.Printf("nox install-ci: wrote %s\n", path)
	fmt.Println("Next:")
	fmt.Println("  1. Commit it. Pull requests are scanned; the schedule watches for new advisories.")
	fmt.Println("  2. The default policy only reports. To have nox prepare fixes, add to .nox.yaml:")
	fmt.Println("       advisories:")
	fmt.Println("         policy: prepare   # report (default) | prepare | remediate")
	fmt.Println("     and give it a bot identity so those pull requests run your required checks:")
	fmt.Println("     a GitHub App (secrets NOX_APP_ID, NOX_APP_PRIVATE_KEY; recommended) or a")
	fmt.Println("     fine-grained token (secret NOX_TOKEN). Without one, the pull request is opened")
	fmt.Println("     with GITHUB_TOKEN, CI will not run on it, and auto-merge stays off.")
	fmt.Println("     Setup: docs/advisory-policy.md#opening-pull-requests-that-run-your-checks")
	if data.Warning != "" {
		fmt.Println("  3. Pin the nox-hq/nox refs to commit SHAs with: nox fix --actions")
	}
	return 0
}

func resolveInstallCI(branch, cron, ref, noxVersion string) (installCIData, error) {
	if !ciSafeValue.MatchString(branch) {
		return installCIData{}, fmt.Errorf("--branch %q must be a plain branch name", branch)
	}
	if !ciCronShape.MatchString(cron) {
		return installCIData{}, fmt.Errorf("--cron %q must be five space-separated cron fields", cron)
	}
	release := version != "" && version != "dev"
	label := ""
	warning := ""
	if ref == "" {
		if !release {
			return installCIData{}, fmt.Errorf("this is a development build with no release tag; pass --nox-ref (a commit SHA of nox-hq/nox)")
		}
		// A tag is a mutable pointer, and nox's own IAC-013 flags it. Pin the
		// commit this release was built from; it is embedded at build time, so
		// there is no network lookup and the answer is deterministic. Without
		// it, refuse rather than write a ref the generated workflow's own scan
		// would flag.
		if !fullSHA.MatchString(commit) {
			return installCIData{}, fmt.Errorf("this build does not record its release commit (commit=%q), so it cannot pin nox-hq/nox to one; pass --nox-ref <commit SHA of v%s>", commit, strings.TrimPrefix(version, "v"))
		}
		ref = commit
		label = " # v" + strings.TrimPrefix(version, "v")
	}
	if !fullSHA.MatchString(ref) {
		warning = fmt.Sprintf("--nox-ref %q is not a full commit SHA; the workflow will pin a movable ref and nox's own IAC-013 will flag it (fix with: nox fix --actions)", ref)
	}
	if !ciSafeValue.MatchString(ref) {
		return installCIData{}, fmt.Errorf("--nox-ref %q must be a plain ref", ref)
	}
	if noxVersion == "" {
		noxVersion = "latest"
		if release {
			noxVersion = strings.TrimPrefix(version, "v")
		}
	}
	if !ciSafeValue.MatchString(noxVersion) {
		return installCIData{}, fmt.Errorf("--nox-version %q must be a plain version", noxVersion)
	}
	return installCIData{Branch: branch, Cron: cron, NoxRef: ref, NoxLabel: label, NoxVersion: noxVersion, Warning: warning}, nil
}

// renderInstallCI fills the workflow template. Its delimiters are [[ ]] because
// the workflow itself is full of ${{ }}.
func renderInstallCI(d installCIData) (string, error) {
	raw, err := templateFS.ReadFile("templates/nox-ci.yml.tmpl")
	if err != nil {
		return "", fmt.Errorf("reading workflow template: %w", err)
	}
	t, err := template.New("nox-ci").Delims("[[", "]]").Option("missingkey=error").Parse(string(raw))
	if err != nil {
		return "", fmt.Errorf("parsing workflow template: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		return "", fmt.Errorf("rendering workflow: %w", err)
	}
	return buf.String(), nil
}
