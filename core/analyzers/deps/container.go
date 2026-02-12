package deps

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
)

// reFromInstruction matches a Dockerfile FROM instruction and captures the
// image reference. It handles optional --platform flags and multi-stage build
// aliases.
//
// Examples matched:
//
//	FROM ubuntu:22.04
//	FROM --platform=linux/amd64 python:3.11-slim AS builder
//	FROM registry.example.com/myimage:v1.2
//	FROM node@sha256:abc123def456
var reFromInstruction = regexp.MustCompile(
	`(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+\S+)?\s*$`,
)

// ParseDockerfile extracts base image references from Dockerfile content.
// Each FROM line produces a Package with Ecosystem "docker". Special images
// like "scratch" and variable references (e.g., ${BASE_IMAGE}) are skipped.
func ParseDockerfile(content []byte) ([]Package, error) {
	var pkgs []Package

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()

		// Skip blank lines and comments.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		matches := reFromInstruction.FindStringSubmatch(trimmed)
		if matches == nil {
			continue
		}

		imageRef := matches[1]

		// Skip the special "scratch" base image.
		if strings.EqualFold(imageRef, "scratch") {
			continue
		}

		// Skip variable references like ${BASE_IMAGE} or $BASE_IMAGE.
		if strings.Contains(imageRef, "$") {
			continue
		}

		name, version := parseImageRef(imageRef)
		if name == "" {
			continue
		}

		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   version,
			Ecosystem: "docker",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pkgs, nil
}

// parseImageRef splits a Docker image reference into name and version.
//
// It handles digest references (name@sha256:...), tagged references
// (name:tag), and untagged references (name defaults to "latest").
//
// Examples:
//
//	"ubuntu:22.04"                        -> ("ubuntu", "22.04")
//	"node@sha256:abc123"                  -> ("node", "sha256:abc123")
//	"registry.example.com/myimage:v1.2"   -> ("registry.example.com/myimage", "v1.2")
//	"ubuntu"                              -> ("ubuntu", "latest")
func parseImageRef(ref string) (name, version string) {
	// Check for digest reference first (name@sha256:...).
	if before, after, ok := strings.Cut(ref, "@"); ok {
		return before, after
	}

	// Split on the last colon to handle registry URLs with ports.
	// For example, "registry.example.com:5000/myimage:v1.2" should split
	// the tag at the last colon after the last slash.
	lastSlash := strings.LastIndex(ref, "/")
	colonIdx := strings.LastIndex(ref, ":")

	// If there is a colon after the last slash, it is a tag separator.
	if colonIdx > lastSlash {
		name = ref[:colonIdx]
		version = ref[colonIdx+1:]
		return name, version
	}

	// No tag and no digest — default to "latest".
	return ref, "latest"
}

// isDockerfile returns true if the filename matches common Dockerfile naming
// patterns: "Dockerfile", "Dockerfile.*" (e.g., Dockerfile.production),
// or "*.dockerfile".
func isDockerfile(filename string) bool {
	base := filepath.Base(filename)

	if base == "Dockerfile" {
		return true
	}

	if strings.HasPrefix(base, "Dockerfile.") {
		return true
	}

	if strings.HasSuffix(strings.ToLower(base), ".dockerfile") {
		return true
	}

	return false
}

// imageIsPinnedToDigest reports whether the image reference includes a
// digest (e.g., ubuntu@sha256:abc123), which provides a cryptographically
// verifiable pin.
func imageIsPinnedToDigest(version string) bool {
	return strings.HasPrefix(version, "sha256:")
}

// imageUsesLatestTag reports whether the image reference uses the "latest"
// tag, either explicitly or implicitly (no tag specified defaults to "latest").
func imageUsesLatestTag(version string) bool {
	return version == "latest"
}

// dockerfileFromLines returns the 1-based line numbers of FROM instructions
// in the given Dockerfile content that would produce packages (i.e., excluding
// scratch and variable references). The returned slice aligns with the output
// of ParseDockerfile so fromLines[i] is the line for packages[i].
func dockerfileFromLines(content []byte) []int {
	var lines []int
	lineNum := 0

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		matches := reFromInstruction.FindStringSubmatch(trimmed)
		if matches == nil {
			continue
		}

		imageRef := matches[1]

		// Mirror the skip logic from ParseDockerfile.
		if strings.EqualFold(imageRef, "scratch") {
			continue
		}
		if strings.Contains(imageRef, "$") {
			continue
		}

		lines = append(lines, lineNum)
	}

	return lines
}
