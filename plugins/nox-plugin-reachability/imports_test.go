package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestExtractGoImports(t *testing.T) {
	dir := t.TempDir()
	goFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(goFile, []byte(`package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

func main() { fmt.Println("hello") }
`), 0o644); err != nil {
		t.Fatal(err)
	}

	imports, err := extractGoImports(goFile)
	if err != nil {
		t.Fatalf("extractGoImports: %v", err)
	}

	want := map[string]bool{
		"fmt":                        true,
		"net/http":                   true,
		"github.com/gorilla/mux":     true,
		"golang.org/x/crypto/bcrypt": true,
	}

	for _, imp := range imports {
		if !want[imp] {
			t.Errorf("unexpected import: %q", imp)
		}
		delete(want, imp)
	}
	for imp := range want {
		t.Errorf("missing import: %q", imp)
	}
}

func TestExtractPyImports(t *testing.T) {
	content := []byte(`import os
import sys
from flask import Flask
from sklearn.model_selection import train_test_split
import json
from PIL import Image
`)

	got := extractPyImports(content)
	sort.Strings(got)

	want := []string{"PIL", "flask", "json", "os", "sklearn", "sys"}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("got %d imports %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("import[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestExtractJSImports(t *testing.T) {
	content := []byte(`import React from 'react';
import { useState } from 'react';
import axios from 'axios';
import { something } from '@scope/package';
const fs = require('fs');
const lodash = require('lodash');
import './local-file';
import '../relative';
`)

	got := extractJSImports(content)
	sort.Strings(got)

	want := []string{"@scope/package", "axios", "fs", "lodash", "react"}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("got %d imports %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("import[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestExtractJSImportsSkipsRelative(t *testing.T) {
	content := []byte(`import foo from './foo';
import bar from '../bar';
import baz from '/absolute/path';
`)

	got := extractJSImports(content)
	if len(got) != 0 {
		t.Errorf("expected no imports for relative/absolute paths, got %v", got)
	}
}

func TestNormalizeJSPackage(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"react", "react"},
		{"react/dom", "react"},
		{"@scope/pkg", "@scope/pkg"},
		{"@scope/pkg/sub/path", "@scope/pkg"},
		{"./local", ""},
		{"../relative", ""},
		{"/absolute", ""},
	}

	for _, tt := range tests {
		got := normalizeJSPackage(tt.input)
		if got != tt.want {
			t.Errorf("normalizeJSPackage(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestPyPIToImportName(t *testing.T) {
	tests := []struct {
		dist string
		want string
	}{
		{"Pillow", "PIL"},
		{"beautifulsoup4", "bs4"},
		{"scikit-learn", "sklearn"},
		{"PyYAML", "yaml"},
		{"opencv-python", "cv2"},
		{"python-dateutil", "dateutil"},
		{"python-dotenv", "dotenv"},
		{"attrs", "attr"},
		{"PyJWT", "jwt"},
		{"flask", "flask"},
		{"requests", "requests"},
		{"my-custom-pkg", "my_custom_pkg"},
	}

	for _, tt := range tests {
		got := PyPIToImportName(tt.dist)
		if got != tt.want {
			t.Errorf("PyPIToImportName(%q) = %q, want %q", tt.dist, got, tt.want)
		}
	}
}

func TestExtractImportsWorkspace(t *testing.T) {
	dir := t.TempDir()

	// Create Go file.
	goDir := filepath.Join(dir, "cmd")
	if err := os.MkdirAll(goDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(goDir, "main.go"), []byte(`package main
import "github.com/example/pkg"
func main() {}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create Python file.
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(`import flask
from requests import get
`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create JS file.
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(`import express from 'express';
const lodash = require('lodash');
`), 0o644); err != nil {
		t.Fatal(err)
	}

	imports, err := ExtractImports(dir)
	if err != nil {
		t.Fatalf("ExtractImports: %v", err)
	}

	checks := []struct {
		eco  string
		name string
		want bool
	}{
		{"Go", "github.com/example/pkg", true},
		{"Go", "github.com/other/pkg", false},
		{"PyPI", "flask", true},
		{"PyPI", "requests", true},
		{"PyPI", "numpy", false},
		{"npm", "express", true},
		{"npm", "lodash", true},
		{"npm", "react", false},
	}

	for _, c := range checks {
		got := imports.Contains(c.eco, c.name)
		if got != c.want {
			t.Errorf("Contains(%q, %q) = %v, want %v", c.eco, c.name, got, c.want)
		}
	}
}

func TestExtractImportsSkipsDirs(t *testing.T) {
	dir := t.TempDir()

	// Create node_modules (should be skipped).
	nmDir := filepath.Join(dir, "node_modules", "react")
	if err := os.MkdirAll(nmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nmDir, "index.js"), []byte(`import something from 'internal-dep';`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create .venv (should be skipped).
	venvDir := filepath.Join(dir, ".venv", "lib")
	if err := os.MkdirAll(venvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(venvDir, "site.py"), []byte(`import _virtualenv`), 0o644); err != nil {
		t.Fatal(err)
	}

	imports, err := ExtractImports(dir)
	if err != nil {
		t.Fatal(err)
	}

	if imports.Contains("npm", "internal-dep") {
		t.Error("should skip node_modules")
	}
	if imports.Contains("PyPI", "_virtualenv") {
		t.Error("should skip .venv")
	}
}

func TestTopLevelModule(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"flask", "flask"},
		{"os.path", "os"},
		{"sklearn.model_selection", "sklearn"},
		{"", ""},
	}

	for _, tt := range tests {
		got := topLevelModule(tt.input)
		if got != tt.want {
			t.Errorf("topLevelModule(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
