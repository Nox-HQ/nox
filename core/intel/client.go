package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client submits observations to an intelligence service.
type Client struct {
	baseURL string
	http    *http.Client
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
	body, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("marshalling observation: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/observations", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

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
