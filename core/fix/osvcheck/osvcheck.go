// Package osvcheck answers fix.Checker from an OSV-protocol endpoint.
package osvcheck

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox-core/vulnsource/osv"
	"github.com/nox-hq/nox/core/fix"
)

// DefaultBaseURL is OSV.dev.
const DefaultBaseURL = "https://api.osv.dev"

// Checker asks an OSV endpoint what a candidate version is still vulnerable to.
type Checker struct {
	BaseURL string
	Client  *http.Client
}

// BaseURLEnv selects the endpoint the scan uses (core.OSVBaseURLEnv), so a
// plan asks the same database the scan did. Duplicated as a literal because
// core imports this planner.
const BaseURLEnv = "NOX_OSV_BASE_URL"

// New returns a Checker; an empty baseURL means $NOX_OSV_BASE_URL, then OSV.dev.
func New(baseURL string) *Checker {
	if baseURL == "" {
		baseURL = strings.TrimRight(strings.TrimSpace(os.Getenv(BaseURLEnv)), "/")
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Checker{BaseURL: baseURL, Client: &http.Client{Timeout: 30 * time.Second}}
}

var _ fix.Checker = (*Checker)(nil)

// Remaining implements fix.Checker. An incomplete answer is an error: an empty
// list from a source that did not answer would read as "clears everything".
func (c *Checker) Remaining(ctx context.Context, ecosystem, pkg, version string) ([]fix.Residual, error) {
	var deg degrade.Degradations
	src := osv.New(c.BaseURL, c.Client, &deg)
	wire := osv.EcosystemName(ecosystem)
	recs, err := src.Lookup(ctx, []vulnsource.Query{{Ecosystem: ecosystem, Name: pkg, Version: version}})
	if err != nil {
		return nil, err
	}
	if deg.Len() > 0 {
		return nil, errors.New("advisory source answered incompletely")
	}
	var out []fix.Residual
	for i := range recs[0] {
		r := &recs[0][i]
		out = append(out, fix.Residual{ID: r.ID, FixedIn: r.FixedVersion(pkg, wire, version)})
	}
	return out, nil
}
