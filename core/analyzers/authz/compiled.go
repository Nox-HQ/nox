package authz

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	nsource "github.com/nox-hq/nox/core/source"
)

// The route readers for compiled-language servers: Go and ASP.NET Core.
// They are kept apart from the JavaScript and Python readers so that a scan
// pays nothing for them in a repository that has neither.

// The framework readers these add.
const (
	ReaderGo     = "Go"
	ReaderASPNET = "ASP.NET Core"
)

type compiledReaders struct {
	goFiles   []*goFile
	csFiles   []*csFile
	csProject map[string]string
}

// read takes a Go or C# artifact; false means the file is none of its business.
func (c *compiledReaders) read(art discovery.Artifact, ext string, raw func() []byte) bool {
	if ext != ".go" && ext != ".cs" {
		return false
	}
	if art.Type != discovery.Source {
		return true
	}
	b := bytes.TrimPrefix(raw(), []byte("\xef\xbb\xbf")) // a byte-order mark is not code
	if len(b) == 0 {
		return true
	}
	p := filepath.ToSlash(art.Path)
	if ext == ".go" {
		c.goFiles = append(c.goFiles, newGoFile(p, b))
		return true
	}
	if c.csProject == nil {
		c.csProject = map[string]string{}
	}
	root := strings.TrimSuffix(filepath.ToSlash(art.AbsPath), p)
	c.csFiles = append(c.csFiles, newCSFile(p, csProjectDir(root, p, c.csProject), b))
	return true
}

func (c *compiledReaders) routes() ([]Route, []routeView) {
	var routes []Route
	var views []routeView
	if len(c.goFiles) > 0 {
		gi := newGoIndex(c.goFiles)
		gi.run()
		r, v := gi.routes()
		routes, views = append(routes, r...), append(views, v...)
	}
	if len(c.csFiles) > 0 {
		r, v := newCSIndex(c.csFiles).routes()
		routes, views = append(routes, r...), append(views, v...)
	}
	return routes, views
}

// readCompiledSource reads a Go or C# source file unless it is a test or generated.
func readCompiledSource(art discovery.Artifact) []byte {
	if nsource.IsTestPath(art.Path) {
		return nil
	}
	b, err := os.ReadFile(art.AbsPath)
	if err != nil || nsource.IsGenerated(b) {
		return nil
	}
	return b
}
