// Package flowunits walks the source files the flow analyzers read and
// extracts each file's taint units.
//
// taintflow and agentflow both run over the same files, in the same order,
// with the same filters, and extraction is most of what either costs: on
// crewAI each spent about ten seconds extracting the same units (#736). A
// scan running both walks once and hands every file's units to each (see
// core/scan.go); an analyzer run on its own walks by itself. Both see the
// files and units this package decides on, so neither can drift from the
// other.
package flowunits

import (
	"context"
	"os"
	"sort"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/source"
	"github.com/nox-hq/nox/core/taint"
	"github.com/nox-hq/nox/core/taint/engine"
)

// Walk calls fn with the units of every Source artifact in a language
// core/lexctx lexes, in path order, so what fn builds is reproducible. It
// stops with ctx's error once ctx is done.
//
// Skipped: files that cannot be read, and generated or minified files (a
// bundle, a vendored dist build): not code this repository wrote, and the
// line recognizer reads a minified line as one enormous statement. The
// generated banner must lead the file; a hand-written tool that emits it as
// data is not generated.
func Walk(ctx context.Context, artifacts []discovery.Artifact, fn func(path string, units []taint.Unit)) error {
	return WalkContent(ctx, artifacts, func(path string, _ []byte, units []taint.Unit) { fn(path, units) })
}

// WalkContent is Walk that also hands fn the file's bytes, for a consumer that
// reads something the units do not carry: the call graph reads a file's
// imports to tell a call into a dependency from a call to a local name.
func WalkContent(ctx context.Context, artifacts []discovery.Artifact, fn func(path string, content []byte, units []taint.Unit)) error {
	ordered := make([]discovery.Artifact, len(artifacts))
	copy(ordered, artifacts)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })

	for i := range ordered {
		if err := ctx.Err(); err != nil {
			return err
		}
		art := &ordered[i]
		if art.Type != discovery.Source {
			continue
		}
		lang := lexctx.LangFromPath(art.Path)
		if lang == lexctx.LangUnknown {
			continue
		}
		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			continue
		}
		if source.IsGeneratedHeader(content) {
			continue
		}
		fn(art.Path, content, engine.ExtractUnits(art.Path, lang, content))
	}
	return nil
}
