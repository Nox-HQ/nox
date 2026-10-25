package mcpconfig

import "testing"

func TestPackageOf(t *testing.T) {
	cases := []struct {
		name string
		l    Launch
		want PackageRef
		ok   bool
	}{
		{"npx pinned scoped", Launch{Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@2025.1.14", "/"}},
			PackageRef{EcosystemNPM, "@modelcontextprotocol/server-filesystem", "2025.1.14", true, "@modelcontextprotocol/server-filesystem@2025.1.14"}, true},
		{"npx pinned unscoped, runner path", Launch{Command: "/usr/local/bin/npx.cmd", Args: []string{"mcp-server-x@1.2.3"}},
			PackageRef{EcosystemNPM, "mcp-server-x", "1.2.3", true, "mcp-server-x@1.2.3"}, true},
		{"npx unpinned", Launch{Command: "npx", Args: []string{"-y", "mcp-server-x"}},
			PackageRef{EcosystemNPM, "mcp-server-x", "", false, "mcp-server-x"}, true},
		{"npx tag is not a pin", Launch{Command: "npx", Args: []string{"@scope/srv@latest"}},
			PackageRef{EcosystemNPM, "@scope/srv", "", false, "@scope/srv@latest"}, true},
		{"npx range is not a pin", Launch{Command: "npx", Args: []string{"srv@^1.2.0"}},
			PackageRef{EcosystemNPM, "srv", "", false, "srv@^1.2.0"}, true},
		{"uvx pinned with ==", Launch{Command: "uvx", Args: []string{"mcp-server-git==0.6.2"}},
			PackageRef{EcosystemPyPI, "mcp-server-git", "0.6.2", true, "mcp-server-git==0.6.2"}, true},
		{"uvx --from", Launch{Command: "uvx", Args: []string{"--from", "Some_Pkg[cli]==1.0", "run"}},
			PackageRef{EcosystemPyPI, "Some_Pkg", "1.0", true, "Some_Pkg[cli]==1.0"}, true},
		{"uvx unpinned", Launch{Command: "uvx", Args: []string{"mcp-server-fetch"}},
			PackageRef{EcosystemPyPI, "mcp-server-fetch", "", false, "mcp-server-fetch"}, true},
		{"git source has no registry identity", Launch{Command: "uvx", Args: []string{"--from", "git+https://github.com/x/y", "y"}}, PackageRef{}, false},
		{"local path", Launch{Command: "npx", Args: []string{"./local-server"}}, PackageRef{}, false},
		{"not a runner", Launch{Command: "node", Args: []string{"server.js"}}, PackageRef{}, false},
		{"docker", Launch{Command: "docker", Args: []string{"run", "-i", "img"}}, PackageRef{}, false},
		{"runner with no package", Launch{Command: "npx", Args: []string{"--help"}}, PackageRef{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := PackageOf(c.l)
			if ok != c.ok || got != c.want {
				t.Errorf("PackageOf(%+v) = %+v, %v; want %+v, %v", c.l, got, ok, c.want, c.ok)
			}
		})
	}
}

func TestNormalizeName(t *testing.T) {
	if NormalizeName(EcosystemPyPI, "Some_Pkg.Name") != "some-pkg-name" || NormalizeName("pypi", "a__b") != "a-b" {
		t.Error("PyPI names follow PEP 503")
	}
	if NormalizeName(EcosystemNPM, "@Scope/Pkg_X") != "@scope/pkg_x" {
		t.Error("npm names are only lower-cased")
	}
}
