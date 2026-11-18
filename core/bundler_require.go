package core

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// bundlerRequiredGems returns the gems a Rails-style application loads at
// boot without any file requiring them, or nil when the tree does not boot
// that way.
//
// `Bundler.require(*Rails.groups)` in config/application.rb requires every gem
// of the Gemfile's default group and of the running environment's group. No
// application file names them, so an import index reads a Rails app as
// importing nothing, and no gem advisory could climb past "the version is
// affected". The environment assumed is production, the one an attacker
// meets: a gem only in development or test groups, or declared
// `require: false`, is not loaded and not returned.
func bundlerRequiredGems(root string) []string {
	app, err := os.ReadFile(filepath.Join(root, "config", "application.rb")) //nolint:gosec // scan root
	if err != nil || !bundlerRequireRE.Match(app) {
		return nil
	}
	gemfile, err := os.ReadFile(filepath.Join(root, "Gemfile")) //nolint:gosec // scan root
	if err != nil {
		return nil
	}
	return productionGems(string(gemfile))
}

var (
	bundlerRequireRE = regexp.MustCompile(`(?m)^\s*Bundler\.require\b`)
	gemLineRE        = regexp.MustCompile(`^gem\s*\(?\s*["']([^"']+)["'](.*)$`)
	groupOpenRE      = regexp.MustCompile(`^group\s*\(?(.*?)\)?\s+do\b`)
	symbolRE         = regexp.MustCompile(`:(\w+)|["'](\w+)["']`)
	requireFalseRE   = regexp.MustCompile(`\brequire\s*:\s*false|:require\s*=>\s*false`)
	inlineGroupRE    = regexp.MustCompile(`\bgroups?\s*:\s*(\[[^\]]*\]|:\w+)|:groups?\s*=>\s*(\[[^\]]*\]|:\w+)`)
)

// productionGems reads a Gemfile's gems loaded under Bundler.require(:default,
// :production). Blocks other than group are tracked only so their `end` does
// not close a group.
func productionGems(gemfile string) []string {
	var stack [][]string // the groups of each open block; nil for a non-group block
	var out []string
	for _, raw := range strings.Split(gemfile, "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		switch line {
		case "":
			continue
		case "end":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if m := groupOpenRE.FindStringSubmatch(line); m != nil {
			stack = append(stack, symbols(m[1]))
			continue
		}
		if m := gemLineRE.FindStringSubmatch(line); m != nil {
			opts := m[2]
			if requireFalseRE.MatchString(opts) {
				continue
			}
			groups := []string{"default"}
			for _, g := range stack {
				if g != nil {
					groups = g
				}
			}
			if gm := inlineGroupRE.FindStringSubmatch(opts); gm != nil {
				groups = symbols(gm[1] + gm[2])
			}
			if loadedInProduction(groups) {
				out = append(out, m[1])
			}
			continue
		}
		if strings.HasSuffix(line, " do") || strings.Contains(line, " do |") {
			// platforms, source, git, path blocks: they do not change groups.
			stack = append(stack, nil)
		}
	}
	return out
}

func symbols(s string) []string {
	var out []string
	for _, m := range symbolRE.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1]+m[2])
	}
	return out
}

func loadedInProduction(groups []string) bool {
	for _, g := range groups {
		if g == "default" || g == "production" {
			return true
		}
	}
	return false
}
