package main

import (
	"testing"
)

func TestExtractRustUses(t *testing.T) {
	src := []byte(`use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use tokio::runtime::Runtime;
extern crate libc;
pub use anyhow::Result;
`)
	got := extractRustUses(src)
	have := map[string]bool{}
	for _, n := range got {
		have[n] = true
	}

	if have["std"] {
		t.Error("std must be excluded as builtin")
	}
	for _, want := range []string{"serde", "tokio", "libc", "anyhow"} {
		if !have[want] {
			t.Errorf("expected crate %s, got %v", want, got)
		}
	}
}

func TestExtractJavaImports(t *testing.T) {
	src := []byte(`package com.example;

import java.util.List;
import javax.annotation.Nullable;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.bind.annotation.RestController;
import com.fasterxml.jackson.databind.ObjectMapper;
import static org.junit.jupiter.api.Assertions.assertTrue;
`)
	got := extractJavaImports(src)
	have := map[string]bool{}
	for _, n := range got {
		have[n] = true
	}

	for _, builtin := range []string{"java.util.List", "javax.annotation.Nullable"} {
		if have[builtin] {
			t.Errorf("%s must be excluded as JDK builtin", builtin)
		}
	}
	for _, want := range []string{
		"org.apache.commons", "org.springframework.web", "com.fasterxml.jackson", "org.junit.jupiter",
	} {
		if !have[want] {
			t.Errorf("expected Maven coordinate %s, got %v", want, got)
		}
	}
}

func TestExtractRubyRequires(t *testing.T) {
	src := []byte(`require 'rails'
require 'json'
require_relative 'helpers/format'
require 'active_record/connection_adapters'
autoload :BCrypt, 'bcrypt'
`)
	got := extractRubyRequires(src)
	have := map[string]bool{}
	for _, n := range got {
		have[n] = true
	}

	for _, want := range []string{"rails", "json", "active_record", "bcrypt"} {
		if !have[want] {
			t.Errorf("expected gem %s, got %v", want, got)
		}
	}
	if have["helpers/format"] || have["helpers"] {
		t.Errorf("relative require should be excluded, got %v", got)
	}
}

func TestExtractCSharpUsings(t *testing.T) {
	src := []byte(`using System;
using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using Serilog.Core;
using static System.Console;
`)
	got := extractCSharpUsings(src)
	have := map[string]bool{}
	for _, n := range got {
		have[n] = true
	}

	if have["System"] || have["System.Collections"] {
		t.Errorf("System.* must be excluded as BCL, got %v", got)
	}
	for _, want := range []string{"Microsoft.Extensions", "Newtonsoft.Json", "Serilog.Core"} {
		if !have[want] {
			t.Errorf("expected NuGet package %s, got %v", want, got)
		}
	}
}

func TestNormalizePackageName_NewEcosystems(t *testing.T) {
	tests := []struct {
		pkg, eco, want string
	}{
		{"some-crate", "crates.io", "some_crate"},
		{"org.springframework:spring-web", "Maven", "org.springframework"},
		{"Rails", "RubyGems", "rails"},
		{"Newtonsoft.Json", "NuGet", "Newtonsoft.Json"},
	}
	for _, tt := range tests {
		if got := normalizePackageName(tt.pkg, tt.eco); got != tt.want {
			t.Errorf("normalizePackageName(%q,%q) = %q, want %q", tt.pkg, tt.eco, got, tt.want)
		}
	}
}
