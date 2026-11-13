package core

import (
	"context"

	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/intel"
)

// intelPOMSource fetches published Maven POMs through NOX Intelligence, so an
// online scan resolves versions managed by spring-boot-starter-parent or an
// imported BOM without contacting anything it does not already ask.
type intelPOMSource struct{ client *intel.Client }

// FetchPOMs asks the service for each coordinate and maps its statuses.
func (s intelPOMSource) FetchPOMs(ctx context.Context, coords []deps.POMCoordinate) ([]deps.POMResult, error) {
	req := make([]intel.MavenCoordinate, len(coords))
	for i, c := range coords {
		req[i] = intel.MavenCoordinate{GroupID: c.Group, ArtifactID: c.Artifact, Version: c.Version}
	}
	answers, err := s.client.MavenPOMs(ctx, req)
	if err != nil {
		return nil, err
	}
	out := make([]deps.POMResult, 0, len(answers))
	for _, a := range answers {
		r := deps.POMResult{
			Coordinate: deps.POMCoordinate{Group: a.GroupID, Artifact: a.ArtifactID, Version: a.Version},
			Status:     deps.POMUnavailable,
		}
		switch a.Status {
		case "found":
			r.Status, r.Content = deps.POMFound, []byte(a.POM)
		case "not_found":
			r.Status = deps.POMNotFound
		}
		// "invalid", "unavailable" and anything newer stay unavailable: none of
		// them says Central lacks the file.
		out = append(out, r)
	}
	return out, nil
}
