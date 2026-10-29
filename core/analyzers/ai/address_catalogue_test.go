package ai

import (
	"context"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

// mcp018Lines scans one file through ScanArtifacts, where the refiners run,
// and returns the lines MCP-018 reported.
func mcp018Lines(t *testing.T, name, src string) []int {
	t.Helper()
	dir := t.TempDir()
	path := writeFile(t, dir, name, src)
	fs, _, err := NewAnalyzer().ScanArtifacts(context.Background(), []discovery.Artifact{
		{Path: name, AbsPath: path, Type: discovery.Source, Size: int64(len(src))},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var lines []int
	for _, f := range fs.Findings() {
		if f.RuleID == "MCP-018" {
			lines = append(lines, f.Location.StartLine)
		}
	}
	return lines
}

// TestMCP018AddressCatalogueIsNotATarget is #929: pydantic-ai's SSRF guard
// lists the metadata addresses it blocks. Nothing near the entries says
// "block" in code (the set is named _CLOUD_METADATA_IPV4, the word sits in a
// comment), so the context keywords cannot see it. What the code does show is
// structure: each address is a bare literal in a collection of nothing but
// addresses, and a fetch target is never written that way.
func TestMCP018AddressCatalogueIsNotATarget(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"guard.py", `_CLOUD_METADATA_IPV4: frozenset[ipaddress.IPv4Address] = frozenset(
    ipaddress.IPv4Address(ip)
    for ip in (
        '169.254.169.254',  # AWS IMDS, GCP, Azure, OCI, DigitalOcean, Hetzner, IBM, OpenStack, ...
        '169.254.170.2',  # AWS ECS task IAM role credentials
        '168.63.129.16',  # Azure WireServer / platform channel (public IP)
        '100.100.100.200',  # Alibaba Cloud
    )
)
_CLOUD_METADATA_IPV6 = frozenset(
    ipaddress.IPv6Address(ip)
    for ip in (
        'fd00:ec2::254',  # AWS IMDS IPv6
        'fd20:ce::254',  # GCP IPv6 (IPv6-only instances)
    )
)
`},
		{"hosts.go", "package x\n\nvar metadataHosts = []string{\"169.254.169.254\", \"metadata.google.internal\", \"fd00:ec2::254\"}\n"},
		{"set.go", "package x\n\nvar blocked = map[string]bool{\n\t\"169.254.169.254\":          true,\n\t\"metadata.google.internal\": true,\n}\n"},
		{"hosts.ts", "export const METADATA = [\n  \"169.254.169.254\", // aws\n  \"100.100.100.200\",\n  \"169.254.0.0/16\",\n];\n"},
	} {
		if got := mcp018Lines(t, c.name, c.src); len(got) != 0 {
			t.Errorf("%s: MCP-018 fired on an address catalogue at lines %v", c.name, got)
		}
	}
}

// TestMCP018StillFiresOnATarget falsifies the refiner: each of these names a
// metadata endpoint as something to reach, or in a collection the code builds
// from more than addresses, and must stay reported.
func TestMCP018StillFiresOnATarget(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"fetch.py", "requests.get(\"http://169.254.169.254/latest/meta-data/iam/\")\n"},
		{"host.py", "host = \"169.254.169.254\"\n"},
		{"one.py", "targets = [\"169.254.169.254\"]\n"},
		{"mixed.py", "targets = [\"169.254.169.254\", base_url]\n"},
		{"urls.py", "targets = [\"http://169.254.169.254/latest\", \"100.100.100.200\"]\n"},
		{"call.py", "probe(\"169.254.169.254\", \"100.100.100.200\")\n"},
		{"map.py", "endpoints = {\"aws\": \"169.254.169.254\", \"ali\": \"100.100.100.200\"}\n"},
		{"keyed.py", "names = {\"169.254.169.254\": \"aws\", \"100.100.100.200\": \"alibaba\"}\n"},
		{"fstr.py", "targets = [f\"{scheme}://169.254.169.254\", \"100.100.100.200\"]\n"},
	} {
		if got := mcp018Lines(t, c.name, c.src); len(got) == 0 {
			t.Errorf("%s: MCP-018 no longer fires on a metadata target", c.name)
		}
	}
}
