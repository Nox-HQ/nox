package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// MavenCoordinate names one published pom.xml.
type MavenCoordinate struct {
	GroupID    string `json:"group_id"`
	ArtifactID string `json:"artifact_id"`
	Version    string `json:"version"`
}

// MavenPOM is the service's answer for one coordinate. Status is "found",
// "not_found", "invalid" or "unavailable"; POM is set only when found.
type MavenPOM struct {
	MavenCoordinate
	Status string `json:"status"`
	POM    string `json:"pom"`
}

// maxMavenAnswer bounds the response: 64 POMs at the service's 2 MB cap.
const maxMavenAnswer = 64 * 2 << 20

// MavenPOMs asks the service for published pom.xml files, which the scanner
// resolves Maven versions from. Only the coordinates are sent — the same kind
// of (group, artifact, version) a dependency lookup sends — and only files
// published to Maven Central come back.
func (c *Client) MavenPOMs(ctx context.Context, coords []MavenCoordinate) ([]MavenPOM, error) {
	body, err := json.Marshal(map[string]any{"coordinates": coords})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/maven/poms", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach NOX Intelligence: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		// An older or reconfigured service: say so, rather than letting every
		// coordinate read as "not on Maven Central".
		return nil, fmt.Errorf("NOX Intelligence at %s does not serve Maven POMs", c.baseURL)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("NOX Intelligence answered HTTP %d for Maven POMs", resp.StatusCode)
	}
	var out struct {
		POMs []MavenPOM `json:"poms"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxMavenAnswer)).Decode(&out); err != nil {
		return nil, fmt.Errorf("unreadable Maven POM answer: %w", err)
	}
	return out.POMs, nil
}
