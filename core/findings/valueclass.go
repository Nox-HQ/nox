package findings

// A secrets rule matches a credential's shape. Sometimes the analyzer can also
// say something about the VALUE that changes what the finding claims: that it
// is one a vendor prints in its documentation, or that it is a key for the
// vendor's sandbox. Such a finding is kept and reclassified, and these keys
// record that it was, so no reader has to infer it from a changed severity.
const (
	// MetaValueClass names what the analyzer established about the value.
	MetaValueClass = "value_class"
	// MetaRuleSeverity is the severity the rule declares, kept when a value
	// class changed the finding's own.
	MetaRuleSeverity = "rule_severity"

	// ValueClassPublishedExample is a value its vendor publishes in
	// documentation. It is public by design and authenticates nothing.
	ValueClassPublishedExample = "published_example"
	// ValueClassTestMode is a credential for a vendor's test environment. It
	// is a real secret that reaches sandbox data only.
	ValueClassTestMode = "test_mode"
)
