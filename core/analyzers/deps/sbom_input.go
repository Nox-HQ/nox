package deps

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// cycloneDXBOM is the minimal structure for CycloneDX JSON BOM input.
type cycloneDXBOM struct {
	Components []struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Purl    string `json:"purl,omitempty"`
		Group   string `json:"group,omitempty"`
	} `json:"components"`
}

// spdxDocument is the minimal structure for SPDX JSON document input.
type spdxDocument struct {
	Packages []struct {
		Name         string `json:"name"`
		VersionInfo  string `json:"versionInfo"`
		ExternalRefs []struct {
			ReferenceType    string `json:"referenceType"`
			ReferenceLocator string `json:"referenceLocator"`
		} `json:"externalRefs,omitempty"`
	} `json:"packages"`
}

// ParseCycloneDXInput reads a CycloneDX JSON BOM and returns a PackageInventory.
func ParseCycloneDXInput(path string) (*PackageInventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CycloneDX BOM %s: %w", path, err)
	}

	pkgs, err := parseCycloneDXContent(data)
	if err != nil {
		return nil, fmt.Errorf("parsing CycloneDX BOM %s: %w", path, err)
	}

	inv := &PackageInventory{}
	for _, p := range pkgs {
		inv.Add(p)
	}
	return inv, nil
}

// parseCycloneDXContent parses CycloneDX JSON content into packages.
func parseCycloneDXContent(content []byte) ([]Package, error) {
	var bom cycloneDXBOM
	if err := json.Unmarshal(content, &bom); err != nil {
		return nil, fmt.Errorf("parsing CycloneDX JSON: %w", err)
	}

	var pkgs []Package
	for _, comp := range bom.Components {
		if comp.Name == "" || comp.Version == "" {
			continue
		}
		eco := ecosystemFromPurl(comp.Purl)
		name := comp.Name
		if comp.Group != "" {
			name = comp.Group + "/" + comp.Name
		}
		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   comp.Version,
			Ecosystem: eco,
		})
	}
	return pkgs, nil
}

// ParseSPDXInput reads an SPDX JSON document and returns a PackageInventory.
func ParseSPDXInput(path string) (*PackageInventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading SPDX document %s: %w", path, err)
	}

	pkgs, err := parseSPDXContent(data)
	if err != nil {
		return nil, fmt.Errorf("parsing SPDX document %s: %w", path, err)
	}

	inv := &PackageInventory{}
	for _, p := range pkgs {
		inv.Add(p)
	}
	return inv, nil
}

// parseSPDXContent parses SPDX JSON content into packages.
func parseSPDXContent(content []byte) ([]Package, error) {
	var doc spdxDocument
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("parsing SPDX JSON: %w", err)
	}

	var pkgs []Package
	for _, sp := range doc.Packages {
		if sp.Name == "" || sp.VersionInfo == "" {
			continue
		}
		eco := "unknown"
		for _, ref := range sp.ExternalRefs {
			if ref.ReferenceType == "purl" {
				eco = ecosystemFromPurl(ref.ReferenceLocator)
				break
			}
		}
		pkgs = append(pkgs, Package{
			Name:      sp.Name,
			Version:   sp.VersionInfo,
			Ecosystem: eco,
		})
	}
	return pkgs, nil
}

// ecosystemFromPurl extracts the ecosystem type from a Package URL.
// Example: "pkg:npm/express@4.18.2" -> "npm"
func ecosystemFromPurl(purl string) string {
	if purl == "" {
		return "unknown"
	}
	// purl format: pkg:type/namespace/name@version
	if !strings.HasPrefix(purl, "pkg:") {
		return "unknown"
	}
	purl = strings.TrimPrefix(purl, "pkg:")
	parts := strings.SplitN(purl, "/", 2)
	if len(parts) < 2 || parts[0] == "" {
		return "unknown"
	}
	return parts[0]
}
