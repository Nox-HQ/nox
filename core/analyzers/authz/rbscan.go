package authz

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	nsource "github.com/nox-hq/nox/core/source"
)

// readRubyAndPHP reads the Rails and Laravel route tables from the artifacts of
// a scan. It is independent of the JavaScript and Python readers: those files
// are never opened here, and these are never opened there.
func readRubyAndPHP(ordered []discovery.Artifact) ([]Route, []routeView) {
	rb := map[string]*rbFile{}
	var rbOrder []string
	for _, art := range ordered {
		p := filepath.ToSlash(art.Path)
		if strings.ToLower(filepath.Ext(p)) != ".rb" || art.Type != discovery.Source || nsource.IsTestPath(art.Path) {
			continue
		}
		if !rbRoutesFileRe.MatchString(p) && !rbDrawnFileRe.MatchString(p) && !rbControllerFileRe.MatchString(p) {
			continue
		}
		raw, err := os.ReadFile(art.AbsPath)
		if err != nil || nsource.IsGenerated(raw) {
			continue
		}
		rb[p] = newRBFile(p, raw)
		rbOrder = append(rbOrder, p)
	}
	var routes []Route
	var views []routeView
	if len(rbOrder) > 0 {
		r, v := readRails(rb, rbOrder)
		routes, views = append(routes, r...), append(views, v...)
	}
	r, v := readPHP(ordered)
	return append(routes, r...), append(views, v...)
}

func readPHP(ordered []discovery.Artifact) ([]Route, []routeView) {
	files := map[string]*phpFile{}
	var order []string
	for _, art := range ordered {
		p := filepath.ToSlash(art.Path)
		if strings.ToLower(filepath.Ext(p)) != ".php" || art.Type != discovery.Source || nsource.IsTestPath(art.Path) {
			continue
		}
		if !phpRoutesFileNameRe.MatchString(p) && !phpControllerFileRe.MatchString(p) && !phpProviderFileRe.MatchString(p) && !phpKernelFileRe.MatchString(p) {
			continue
		}
		raw, err := os.ReadFile(art.AbsPath)
		if err != nil || nsource.IsGenerated(raw) {
			continue
		}
		files[p] = newPHPFile(p, raw)
		order = append(order, p)
	}
	if len(order) == 0 {
		return nil, nil
	}
	return readLaravel(files, order)
}
