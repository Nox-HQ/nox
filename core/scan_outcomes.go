package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/git"
	"github.com/nox-hq/nox/core/intel"
)

// OutcomeReport is what a scan of target would send as its outcome report, and
// how many dependency findings were left out of it (values the service would
// refuse, or more than one report holds). It reads the repository's root
// commit and derives the reporter identity and project pseudonym from the
// local salt; it sends nothing. `nox intel preview --outcomes` prints it.
func OutcomeReport(target, saltPath, toolVersion string, fs []findings.Finding, now time.Time) (intel.OutcomeReport, int, error) {
	var r intel.OutcomeReport
	root, err := git.RootCommit(scanRootDir(target))
	if err != nil {
		return r, 0, err
	}
	project, err := intel.ProjectPseudonym(saltPath, root)
	if err != nil {
		return r, 0, fmt.Errorf("project pseudonym: %w", err)
	}
	reporterID, err := intel.ReporterID(saltPath)
	if err != nil {
		return r, 0, fmt.Errorf("reporter identity: %w", err)
	}
	delKey, err := intel.DeletionKey(saltPath)
	if err != nil {
		return r, 0, fmt.Errorf("deletion key: %w", err)
	}
	out, skipped := intel.DeriveOutcomeFindings(fs)
	return intel.OutcomeReport{
		SchemaVersion:    intel.OutcomeSchemaVersion,
		ConsentVersion:   intel.TermsVersion,
		OutcomeTerms:     intel.OutcomeTermsVersion,
		ReporterID:       reporterID,
		DeletionVerifier: intel.DeletionVerifier(delKey),
		Project:          project,
		ObservedAt:       now.UTC().Format(time.RFC3339),
		ToolVersion:      toolVersion,
		Findings:         out,
	}, skipped, nil
}

// contributeOutcomes sends this scan's outcome report, if this installation
// opted in to both contribution and outcome reports.
//
// Every gate that fails says so, like contributeObservations: an outcome
// report that quietly stopped is invisible otherwise. Failure is recorded,
// never propagated. The report is always anonymous, even when contributions
// are attested: a project pseudonym joined to an organisation would name
// whose project it is.
func contributeOutcomes(ctx context.Context, cfg *ScanConfig, opts ScanOptions, target string, fs []findings.Finding, deg *degrade.Degradations) {
	ic := cfg.Scan.Intelligence
	endpoint := ic.ResolvedEndpoint()
	if !opts.ContributeObservations || !ic.Outcomes || endpoint == "" {
		return
	}
	if !ic.Contribute {
		deg.Add(degrade.IntelContribution,
			"scan.intelligence.outcomes is set but scan.intelligence.contribute is not",
			"no outcome report was sent: outcome reports ride on contribution and its terms. "+
				"The scan's own findings are unaffected")
		return
	}
	if status, _ := intel.LoadConsent(ic.ReporterSaltPath); status != intel.ConsentGranted {
		// contributeObservations has already said why; one message is enough.
		return
	}
	switch status, rec := intel.LoadOutcomeConsent(ic.ReporterSaltPath); status {
	case intel.ConsentGranted:
	case intel.ConsentStale:
		deg.Add(degrade.IntelContribution,
			fmt.Sprintf("outcome reports are paused: you accepted outcome terms %s and the current terms are %s",
				rec.TermsVersion, intel.OutcomeTermsVersion),
			"no outcome report was sent; read the new terms with `nox intel consent outcomes show` "+
				"and accept them with `nox intel consent outcomes accept`")
		return
	default:
		deg.Add(degrade.IntelContribution,
			"scan.intelligence.outcomes is set but this machine has not accepted the outcome terms",
			"no outcome report was sent; read the terms with `nox intel consent outcomes show` and "+
				"accept them with `nox intel consent outcomes accept`")
		return
	}

	report, skipped, err := OutcomeReport(target, ic.ReporterSaltPath, opts.ToolVersion, fs, time.Now())
	if err != nil {
		why := "this project has no identity nox can derive a pseudonym from"
		if errors.Is(err, git.ErrShallowClone) {
			why = "this is a shallow clone, whose apparent first commit changes with every fetch; " +
				"in CI, fetch the full history (actions/checkout: fetch-depth: 0)"
		}
		deg.Add(degrade.IntelContribution,
			fmt.Sprintf("no outcome report was sent: %v", err),
			why+". Nothing left this environment for it. The scan's own findings are unaffected")
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := intel.NewClient(endpoint, intelHTTPClient()).SubmitOutcome(ctx, report); err != nil {
		deg.Add(degrade.IntelContribution,
			fmt.Sprintf("the outcome report was not accepted: %v", err),
			"this scan's outcome was not recorded; the scan's own findings are unaffected")
		return
	}
	if skipped > 0 {
		deg.Add(degrade.IntelContribution,
			fmt.Sprintf("the outcome report left out %d of its dependency findings", skipped),
			"their values were outside what the service accepts, or the report was over its size bound; "+
				"`nox intel preview --outcomes` shows what was sent")
	}
}
