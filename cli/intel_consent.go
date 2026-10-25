package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/intel"
)

// saltPathFor resolves where this installation's reporter salt lives:
// scan.intelligence.reporter_salt_path from the config in the working
// directory when set, otherwise the default. The scan resolves it the same way,
// so consent, id and erasure always speak about one installation.
func saltPathFor(override string) string {
	if override != "" {
		return override
	}
	if cfg, err := core.LoadScanConfig("."); err == nil && cfg != nil {
		return cfg.Scan.Intelligence.ReporterSaltPath
	}
	return ""
}

// runIntelConsent manages the contribution terms acceptance on this machine.
func runIntelConsent(args []string) int {
	return intelConsent(args, os.Stdin, os.Stdout, os.Stderr)
}

func intelConsent(args []string, in io.Reader, out, errw io.Writer) int {
	sub := "status"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("intel consent", flag.ContinueOnError)
	fs.SetOutput(errw)
	salt := fs.String("salt-path", "", "reporter salt path (default: config or ~/.nox/reporter-salt)")
	accept := fs.String("accept-terms", "", "accept non-interactively; must name the current terms version ("+intel.TermsVersion+")")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	sp := saltPathFor(*salt)

	switch sub {
	case "show":
		_, _ = fmt.Fprint(out, intel.Terms)
		return 0
	case "status":
		return consentStatus(sp, out)
	case "accept":
		return consentAccept(sp, *accept, in, out, errw)
	case "withdraw":
		if err := intel.WithdrawConsent(sp); err != nil {
			_, _ = fmt.Fprintf(errw, "nox intel consent: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintln(out, "Consent withdrawn. This machine will not contribute. Reports already sent stay on the service until you run: nox intel forget")
		return 0
	default:
		_, _ = fmt.Fprintf(errw, "Usage: nox intel consent [show|status|accept|withdraw]\n")
		return 2
	}
}

func consentStatus(salt string, out io.Writer) int {
	status, rec := intel.LoadConsent(salt)
	switch status {
	case intel.ConsentGranted:
		_, _ = fmt.Fprintf(out, "Terms %s accepted at %s. Contribution still needs scan.intelligence.contribute: true.\n", rec.TermsVersion, rec.AcceptedAt)
	case intel.ConsentStale:
		_, _ = fmt.Fprintf(out, "Terms %s were accepted; the current terms are %s. Contribution is paused until you run: nox intel consent accept\n", rec.TermsVersion, intel.TermsVersion)
	default:
		_, _ = fmt.Fprintf(out, "No terms accepted on this machine. Contribution is off. Read them: nox intel consent show\n")
	}
	return 0
}

func consentAccept(salt, flagVersion string, in io.Reader, out, errw io.Writer) int {
	if flagVersion != "" {
		if flagVersion != intel.TermsVersion {
			_, _ = fmt.Fprintf(errw, "nox intel consent: --accept-terms=%s, but the current terms are %s; read them with `nox intel consent show`\n", flagVersion, intel.TermsVersion)
			return 1
		}
	} else {
		_, _ = fmt.Fprint(out, intel.Terms)
		_, _ = fmt.Fprintf(out, "\nType %q to accept these terms: ", "yes")
		line, _ := bufio.NewReader(in).ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "yes" {
			_, _ = fmt.Fprintln(errw, "nox intel consent: not accepted; nothing recorded")
			return 1
		}
	}
	if err := intel.RecordConsent(salt, time.Now().UTC().Format(time.RFC3339)); err != nil {
		_, _ = fmt.Fprintf(errw, "nox intel consent: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(out, "Accepted terms %s on this machine. Contribution also needs scan.intelligence.contribute: true.\n", intel.TermsVersion)
	return 0
}

// runIntelForget erases this installation's reporter id from the service and,
// only once the service has confirmed, withdraws consent locally. If the
// service cannot be reached or refuses, nothing changes locally: a local
// "forgotten" state with the data still on the server would be a false all-clear.
func runIntelForget(args []string) int {
	return intelForget(args, os.Stdout, os.Stderr)
}

func intelForget(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("intel forget", flag.ContinueOnError)
	fs.SetOutput(errw)
	endpoint := fs.String("endpoint", intelEndpointDefault(), "intelligence service base URL")
	salt := fs.String("salt-path", "", "reporter salt path (default: config or ~/.nox/reporter-salt)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	sp := saltPathFor(*salt)

	id, found, err := intel.ExistingIdentity(sp)
	if err != nil {
		_, _ = fmt.Fprintf(errw, "nox intel forget: %v\n", err)
		return 1
	}
	if !found {
		_, _ = fmt.Fprintln(out, "This machine has no reporter identity, so it has never contributed. Nothing to erase.")
		if err := intel.WithdrawConsent(sp); err != nil {
			_, _ = fmt.Fprintf(errw, "nox intel forget: %v\n", err)
			return 1
		}
		return 0
	}
	if *endpoint == "" {
		_, _ = fmt.Fprintln(errw, "nox intel forget: no intelligence endpoint is configured; nothing was changed")
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := intel.NewClient(*endpoint, nil).Erase(ctx, id.ReporterID, id.DeletionKey)
	if err != nil {
		_, _ = fmt.Fprintf(errw, "nox intel forget: %v\nNothing was changed on this machine; contribution settings are as they were. Retry when the service is reachable.\n", err)
		return 1
	}
	if err := intel.WithdrawConsent(sp); err != nil {
		_, _ = fmt.Fprintf(errw, "nox intel forget: erased on the service, but %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(out, "Erased from %s: %d report(s) unlinked from this installation, %d identifier(s) removed, consent record removed: %t (proof: %s).\n",
		*endpoint, res.CandidatesAnonymised, res.IdentifiersRemoved, res.ConsentRemoved, res.Proof)
	_, _ = fmt.Fprintln(out, "Contribution is now off on this machine (consent withdrawn). Set scan.intelligence.contribute: false in project config to stop the scan mentioning it.")
	return 0
}
