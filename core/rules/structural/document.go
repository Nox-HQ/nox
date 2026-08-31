// Package structural parses Infrastructure-as-Code documents and resolves
// resources and their properties, so an absence rule can ask "does this
// resource actually set this attribute?" instead of "does this pattern appear
// somewhere near it?".
//
// # Why this exists
//
// The IAC family is 490 rules of regex and absence matching, and nothing in it
// parses the document. A regex match over YAML is a heuristic however specific
// the pattern, so no IAC finding can carry a claim stronger than "a pattern
// matched" — which is what makes the family, by the migration measure, entirely
// unmigrated.
//
// Absence rules are where structure pays first, and in both directions:
//
//   - A property the pattern could not see is a FALSE POSITIVE today. A bucket
//     that sets encryption through an anchor, a nested key, or a spelling the
//     alternation misses is reported as unencrypted. Parsing refutes that
//     deterministically.
//   - A property the parser confirms is missing is a claim a regex cannot make.
//     "The resource was parsed and has no BucketEncryption property" is static
//     analysis; "no pattern matched inside a span I guessed by indentation" is
//     not.
//
// # What it deliberately does not do
//
// It does not evaluate the document. Intrinsic functions (`!Ref`, `!GetAtt`,
// `[[ parameters() ]]`) are read as the values they syntactically are, never
// resolved — resolving them would need the deployment context, which is not in
// the file. A property whose value is an unresolved reference counts as
// PRESENT, because the template author did set it; whether it resolves to
// something safe is a question this file cannot answer.
//
// It is pure and deterministic: same bytes, same resources, no clock, no I/O.
package structural

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// maxDocumentSize bounds what will be parsed. IaC templates are human-authored
// and small; something far larger is either generated state or an attempt to
// make the parser the expensive part of a scan. Refusing is safe because the
// caller falls back to the regex path, which is what runs today.
const maxDocumentSize = 4 << 20 // 4 MiB

// maxAliasDepth bounds alias following. YAML anchors can be made to expand
// exponentially ("billion laughs"); this parser only ever follows an alias to
// read a value, so a small constant depth is enough for real documents and
// removes the amplification entirely.
const maxAliasDepth = 32

// ErrTooLarge is returned by Parse for content above maxDocumentSize.
var ErrTooLarge = errors.New("document too large to parse structurally")

// Parse parses content as a stream of YAML documents.
//
// JSON goes through the same path deliberately: JSON is a subset of YAML 1.2,
// so one parser covers CloudFormation and ARM templates in either notation
// without a second code path that could disagree with the first about what a
// document contains.
//
// An error means only that the structural path is unavailable for this content;
// every caller falls back to text matching, so a malformed document degrades to
// today's behaviour rather than to silence.
func Parse(content []byte) ([]*yaml.Node, error) {
	if len(content) > maxDocumentSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(content))
	}

	var docs []*yaml.Node
	dec := yaml.NewDecoder(newByteReader(content))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err != nil {
			// io.EOF ends the stream normally. Any other error means the
			// content is not valid YAML; the documents decoded so far are
			// still well-formed, but a partially-parsed file is exactly the
			// case where the structural verdict would be unsound, so nothing
			// is returned.
			if isEOF(err) {
				break
			}
			return nil, err
		}
		if doc.Kind == 0 {
			// An empty document (`---` with nothing after it) decodes to a
			// zero node. It contains no resources; skipping it is not a
			// degradation.
			continue
		}
		docs = append(docs, &doc)
	}
	if len(docs) == 0 {
		return nil, errors.New("no YAML documents")
	}
	return docs, nil
}

// root returns the content node of a document node, following the single
// wrapper yaml.v3 puts around every parsed document.
func root(doc *yaml.Node) *yaml.Node {
	if doc == nil {
		return nil
	}
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return nil
		}
		return doc.Content[0]
	}
	return doc
}

// resolve follows alias nodes to the node they refer to.
//
// Depth is bounded rather than trusted: an alias chain is attacker-controllable
// in a scanned repository, and a parser that recurses on it is a denial of
// service in a tool that runs in CI.
func resolve(n *yaml.Node) *yaml.Node {
	for depth := 0; n != nil && n.Kind == yaml.AliasNode; depth++ {
		if depth >= maxAliasDepth {
			return nil
		}
		n = n.Alias
	}
	return n
}

// mapValue returns the value node for key in a mapping node, or nil.
//
// Comparison is case-sensitive because every schema this package understands
// is: CloudFormation writes `Properties`, Kubernetes writes `spec`, and ARM
// writes `properties`. Matching case-insensitively would let a key the schema
// does not define satisfy a lookup, which for an absence rule means silently
// dropping a real finding.
func mapValue(n *yaml.Node, key string) *yaml.Node {
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	// Content alternates key, value, key, value.
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return resolve(n.Content[i+1])
		}
	}
	return nil
}

// scalarAt returns the string value of a scalar child, or "".
func scalarAt(n *yaml.Node, key string) string {
	v := mapValue(n, key)
	if v == nil || v.Kind != yaml.ScalarNode {
		return ""
	}
	return v.Value
}
