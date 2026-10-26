package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nox-hq/nox-core/evidence"
)

// Client submits observations to an intelligence service.
type Client struct {
	baseURL string
	http    *http.Client
	// token, when set, authenticates every request as an organisation. Scan
	// observations then go to the attested route, where the service derives the
	// source from the organisation and counts it as an independent source; the
	// reporter id is ignored there. Empty keeps the anonymous route.
	token string
}

// WithToken returns a client that authenticates as an organisation (an
// organisation token, never an operator session). It changes what the service
// can know: an attested contribution can be joined to its organisation, which
// is the price of counting as an independent source.
func (c *Client) WithToken(token string) *Client {
	cp := *c
	cp.token = strings.TrimSpace(token)
	return &cp
}

// NewClient returns a client for the service at baseURL.
func NewClient(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

// Result reports what a contribution achieved.
type Result struct {
	Submitted int
	Accepted  int
	Rejected  int
	// FirstError is the first rejection or transport failure, for reporting.
	FirstError error
}

// Contribute submits observations one at a time.
//
// Failures never propagate to the scan. Contributing is a courtesy to the
// network; a scan that failed because an upload did would make opting in
// actively hostile, and would give operators a reason to turn off the thing
// that makes corroboration possible. The caller records the outcome as a
// degradation so a contribution that is quietly failing is still visible.
func (c *Client) Contribute(ctx context.Context, obs []Observation) Result {
	res := Result{Submitted: len(obs)}
	for i := range obs {
		if err := c.submit(ctx, &obs[i]); err != nil {
			res.Rejected++
			if res.FirstError == nil {
				res.FirstError = err
			}
			continue
		}
		res.Accepted++
	}
	return res
}

func (c *Client) submit(ctx context.Context, o *Observation) error {
	// Structural, not advisory: an observation that cannot name the terms its
	// operator accepted is not sent, whoever built it.
	if o.ConsentVersion == "" {
		return errors.New("observation carries no consent_version; not sent")
	}
	body, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("marshalling observation: %w", err)
	}

	path := "/v1/observations"
	if c.token != "" {
		path = "/v1/attested/observations"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error != "" {
			// The service returns the reason in full for a rejected
			// observation, and the reason describes this client's own request.
			// A client whose redaction has regressed needs to be told which
			// field it leaked.
			return fmt.Errorf("observation rejected: %s", e.Error)
		}
		return fmt.Errorf("observation rejected with status %d", resp.StatusCode)
	}
	return nil
}

// ErasureResult is what the service reports it removed.
type ErasureResult struct {
	CandidatesAnonymised int    `json:"candidates_anonymised"`
	IdentifiersRemoved   int    `json:"identifiers_removed"`
	ConsentRemoved       bool   `json:"consent_removed"`
	Proof                string `json:"proof"`
}

// Erase asks the service to remove reporterID from every report. It is a POST
// with a body so the id never appears in a logged path. Any answer other than
// 200 is an error: the caller must not treat an unconfirmed erasure as done.
func (c *Client) Erase(ctx context.Context, reporterID, deletionKey string) (ErasureResult, error) {
	var res ErasureResult
	body, err := json.Marshal(map[string]string{
		"reporter_id": reporterID, "deletion_key": deletionKey,
	})
	if err != nil {
		return res, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/reporters/erase", bytes.NewReader(body))
	if err != nil {
		return res, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return res, fmt.Errorf("could not reach the service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error != "" {
			return res, fmt.Errorf("erasure refused (status %d): %s", resp.StatusCode, e.Error)
		}
		return res, fmt.Errorf("erasure refused with status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return res, fmt.Errorf("erasure answer unreadable (nothing confirmed): %w", err)
	}
	return res, nil
}

// RunReceipt is what the service says about a contributed run.
type RunReceipt struct {
	CandidateID    string `json:"candidate_id"`
	AttackReporter int    `json:"attack_reporters"`
	Scope          string `json:"scope"`
	InExposureView bool   `json:"recorded_in_exposure_view"`
}

// SubmitRun sends one attack-run report to the attested route. It needs a
// token: reporter-scoped evidence from an unattested source is refused by the
// service, so it is refused here first rather than sent to be refused.
func (c *Client) SubmitRun(ctx context.Context, r evidence.RunReport) (RunReceipt, error) {
	var rc RunReceipt
	if c.token == "" {
		return rc, errors.New("attack evidence needs an organisation token (NOX_INTEL_TOKEN); not sent")
	}
	if err := r.Validate(); err != nil {
		return rc, fmt.Errorf("run report not sent: %w", err)
	}
	body, err := json.Marshal(r)
	if err != nil {
		return rc, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/attested/attack-runs", bytes.NewReader(body))
	if err != nil {
		return rc, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return rc, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&e)
		switch {
		case resp.StatusCode == http.StatusUnauthorized:
			return rc, errors.New("the service did not accept NOX_INTEL_TOKEN as an organisation token")
		case resp.StatusCode == http.StatusNotFound:
			return rc, errors.New("the service has no candidate it can attach this run to (unknown, or not yet public and not reported by you)")
		case e.Error != "":
			return rc, fmt.Errorf("run rejected: %s", e.Error)
		}
		return rc, fmt.Errorf("run rejected with status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&rc); err != nil {
		return rc, fmt.Errorf("receipt unreadable (the run may have been recorded): %w", err)
	}
	return rc, nil
}

// EraseAttested asks the service to anonymise every contribution made by the
// token's organisation. Any answer other than 200 is an error: an unconfirmed
// erasure must not be treated as done.
func (c *Client) EraseAttested(ctx context.Context) (ErasureResult, error) {
	var res ErasureResult
	if c.token == "" {
		return res, errors.New("erasing attested contributions needs an organisation token (NOX_INTEL_TOKEN)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/attested/erase", strings.NewReader("{}"))
	if err != nil {
		return res, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return res, fmt.Errorf("could not reach the service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("erasure refused with status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&res); err != nil {
		return res, fmt.Errorf("erasure answer unreadable (nothing confirmed): %w", err)
	}
	return res, nil
}
