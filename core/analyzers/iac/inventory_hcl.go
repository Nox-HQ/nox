package iac

import (
	"sort"
	"strings"
)

// This file is a deliberately small reader for HCL: enough to find blocks, their
// labels, their attributes and their nested blocks. It evaluates nothing. An
// attribute value is kept as the text the author wrote, and a caller that needs
// a boolean or a string asks for it with literalBool / literalString, which
// refuse anything that is an expression. That refusal is the point: "was
// `false`, now `var.public`" must not be read as a change of value.
//
// The reason it exists beside the byte-level brace matching the Terraform rules
// use is that those rules ask one question of one span, while the inventory has
// to answer "which flags does this block set" for every resource, including the
// ones that are configured correctly and therefore produce no finding.

// hclBlock is one block: `resource "aws_s3_bucket" "uploads" { ... }`.
type hclBlock struct {
	typ      string
	labels   []string
	attrs    map[string]string
	children []*hclBlock
	line     int
	endLine  int
}

func (b *hclBlock) child(typ string) *hclBlock {
	for _, c := range b.children {
		if c.typ == typ {
			return c
		}
	}
	return nil
}

func (b *hclBlock) childrenOf(typ string) []*hclBlock {
	var out []*hclBlock
	for _, c := range b.children {
		if c.typ == typ {
			out = append(out, c)
		}
	}
	return out
}

type hclScanner struct {
	src  []byte
	pos  int
	line []int // offset of the start of each line
}

// parseHCL returns the top-level blocks of src.
func parseHCL(src []byte) []*hclBlock {
	s := &hclScanner{src: blankHCLComments(src)}
	s.line = append(s.line, 0)
	for i, c := range s.src {
		if c == '\n' {
			s.line = append(s.line, i+1)
		}
	}
	blocks, _ := s.body(false)
	return blocks
}

// lineAt returns the 1-based line of an offset.
func (s *hclScanner) lineAt(off int) int {
	return sort.Search(len(s.line), func(i int) bool { return s.line[i] > off })
}

// body parses blocks and attributes until the closing brace (or the end of the
// input when top-level). Top-level attributes are ignored.
func (s *hclScanner) body(nested bool) (blocks []*hclBlock, attrs map[string]string) {
	attrs = map[string]string{}
	for {
		s.skipSpace()
		if s.pos >= len(s.src) {
			return blocks, attrs
		}
		if s.src[s.pos] == '}' {
			if nested {
				return blocks, attrs
			}
			s.pos++
			continue
		}
		start := s.pos
		name := s.ident()
		if name == "" {
			s.skipLine()
			continue
		}
		s.skipInline()
		if s.pos < len(s.src) && s.src[s.pos] == '=' && (s.pos+1 >= len(s.src) || s.src[s.pos+1] != '=') {
			s.pos++
			attrs[name] = strings.TrimSpace(s.expression())
			continue
		}
		var labels []string
		for s.pos < len(s.src) && (s.src[s.pos] == '"' || isIdentByte(s.src[s.pos])) {
			if s.src[s.pos] == '"' {
				labels = append(labels, s.quoted())
			} else {
				labels = append(labels, s.ident())
			}
			s.skipInline()
		}
		if s.pos >= len(s.src) || s.src[s.pos] != '{' {
			s.skipLine()
			continue
		}
		s.pos++
		b := &hclBlock{typ: name, labels: labels, line: s.lineAt(start)}
		b.children, b.attrs = s.body(true)
		if s.pos < len(s.src) && s.src[s.pos] == '}' {
			b.endLine = s.lineAt(s.pos)
			s.pos++
		} else {
			b.endLine = s.lineAt(len(s.src) - 1)
		}
		blocks = append(blocks, b)
	}
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '-' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func (s *hclScanner) skipSpace() {
	for s.pos < len(s.src) {
		switch s.src[s.pos] {
		case ' ', '\t', '\r', '\n', ',':
			s.pos++
		default:
			return
		}
	}
}

func (s *hclScanner) skipInline() {
	for s.pos < len(s.src) && (s.src[s.pos] == ' ' || s.src[s.pos] == '\t') {
		s.pos++
	}
}

func (s *hclScanner) skipLine() {
	for s.pos < len(s.src) && s.src[s.pos] != '\n' {
		s.pos++
	}
}

func (s *hclScanner) ident() string {
	start := s.pos
	for s.pos < len(s.src) && isIdentByte(s.src[s.pos]) {
		s.pos++
	}
	return string(s.src[start:s.pos])
}

func (s *hclScanner) quoted() string {
	s.pos++ // opening quote
	start := s.pos
	for s.pos < len(s.src) && s.src[s.pos] != '"' {
		if s.src[s.pos] == '\\' {
			s.pos++
		}
		s.pos++
	}
	out := string(s.src[start:min(s.pos, len(s.src))])
	s.pos++
	return out
}

// expression reads an attribute value: up to the end of the line, continuing
// while brackets are open or a heredoc is unterminated.
func (s *hclScanner) expression() string {
	start := s.pos
	depth := 0
	for s.pos < len(s.src) {
		c := s.src[s.pos]
		switch {
		case c == '"':
			s.skipString()
			continue
		case c == '<' && s.pos+1 < len(s.src) && s.src[s.pos+1] == '<':
			s.skipHeredoc()
			continue
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			if depth == 0 {
				return string(s.src[start:s.pos])
			}
			depth--
		case c == '\n' && depth == 0:
			return string(s.src[start:s.pos])
		}
		s.pos++
	}
	return string(s.src[start:])
}

// skipString advances past a double-quoted string, including `${ ... }`
// interpolations that contain quotes of their own.
func (s *hclScanner) skipString() {
	s.pos++
	for s.pos < len(s.src) {
		switch s.src[s.pos] {
		case '\\':
			s.pos += 2
			continue
		case '"':
			s.pos++
			return
		case '$', '%':
			if s.pos+1 < len(s.src) && s.src[s.pos+1] == '{' {
				s.skipInterpolation()
				continue
			}
		}
		s.pos++
	}
}

func (s *hclScanner) skipInterpolation() {
	depth := 0
	for s.pos < len(s.src) {
		switch s.src[s.pos] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				s.pos++
				return
			}
		case '"':
			s.skipString()
			continue
		}
		s.pos++
	}
}

// skipHeredoc advances past `<<TAG` ... `TAG`.
func (s *hclScanner) skipHeredoc() {
	p := s.pos + 2
	if p < len(s.src) && s.src[p] == '-' {
		p++
	}
	start := p
	for p < len(s.src) && isIdentByte(s.src[p]) {
		p++
	}
	tag := string(s.src[start:p])
	if tag == "" {
		s.pos += 2
		return
	}
	for p < len(s.src) && s.src[p] != '\n' {
		p++
	}
	for p < len(s.src) {
		p++ // the newline
		end := p
		for end < len(s.src) && s.src[end] != '\n' {
			end++
		}
		if strings.TrimSpace(string(s.src[p:end])) == tag {
			s.pos = end
			return
		}
		p = end
	}
	s.pos = len(s.src)
}

// blankHCLComments replaces comments with spaces, keeping every newline so line
// numbers survive, and leaves strings and heredocs alone.
func blankHCLComments(src []byte) []byte {
	out := append([]byte(nil), src...)
	s := &hclScanner{src: out}
	for s.pos < len(out) {
		c := out[s.pos]
		switch {
		case c == '"':
			s.skipString()
		case c == '<' && s.pos+1 < len(out) && out[s.pos+1] == '<':
			s.skipHeredoc()
		case c == '#' || c == '/' && s.pos+1 < len(out) && out[s.pos+1] == '/':
			for s.pos < len(out) && out[s.pos] != '\n' {
				out[s.pos] = ' '
				s.pos++
			}
		case c == '/' && s.pos+1 < len(out) && out[s.pos+1] == '*':
			for s.pos < len(out) && (out[s.pos] != '*' || s.pos+1 >= len(out) || out[s.pos+1] != '/') {
				if out[s.pos] != '\n' {
					out[s.pos] = ' '
				}
				s.pos++
			}
			if s.pos+1 < len(out) {
				out[s.pos], out[s.pos+1] = ' ', ' '
				s.pos += 2
			}
		default:
			s.pos++
		}
	}
	return out
}

// literalBool reads true or false, and reports ok only for those two words. A
// quoted "true" is also accepted: Terraform converts it.
func literalBool(expr string) (value, ok bool) {
	switch strings.Trim(strings.TrimSpace(expr), `"`) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// literalString reads a plain double-quoted string with no interpolation.
func literalString(expr string) (string, bool) {
	e := strings.TrimSpace(expr)
	if len(e) < 2 || e[0] != '"' || e[len(e)-1] != '"' {
		return "", false
	}
	inner := e[1 : len(e)-1]
	if strings.ContainsAny(inner, "$%\\\"") {
		return "", false
	}
	return inner, true
}

// literalStrings reads a list of plain strings; ok is false when any element
// is an expression.
func literalStrings(expr string) ([]string, bool) {
	e := strings.TrimSpace(expr)
	if len(e) < 2 || e[0] != '[' || e[len(e)-1] != ']' {
		return nil, false
	}
	var out []string
	for _, part := range strings.Split(e[1:len(e)-1], ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, ok := literalString(part)
		if !ok {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}
