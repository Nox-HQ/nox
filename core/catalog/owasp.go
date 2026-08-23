package catalog

import "strings"

// OWASPLLMEdition names the edition of the "OWASP Top 10 for LLM Applications"
// that Nox's LLM taxonomy is mapped to. The 2023 and 2025 editions renumber the
// same underlying risks, so emitting the edition alongside a category lets
// downstream consumers state which list a number refers to.
const OWASPLLMEdition = "2025"

// OWASPLLM is a category in the OWASP Top 10 for LLM Applications (2025 edition).
//
// This is the single source of truth for LLM category numbering across Nox.
// Analyzers, rules, and reports must reference these constants (or the helpers
// below) rather than restating the taxonomy as bare string literals, so the
// numbering cannot drift between call sites.
type OWASPLLM string

// The ten 2025 categories. The 2023 -> 2025 renumbering is non-trivial (several
// categories were merged, split, or reordered), which is precisely why the
// mapping lives here and nowhere else.
const (
	LLM01PromptInjection         OWASPLLM = "LLM01" // Prompt Injection
	LLM02SensitiveInfoDisclosure OWASPLLM = "LLM02" // Sensitive Information Disclosure
	LLM03SupplyChain             OWASPLLM = "LLM03" // Supply Chain
	LLM04DataModelPoisoning      OWASPLLM = "LLM04" // Data and Model Poisoning
	LLM05ImproperOutputHandling  OWASPLLM = "LLM05" // Improper Output Handling
	LLM06ExcessiveAgency         OWASPLLM = "LLM06" // Excessive Agency (absorbs 2023 LLM07 Insecure Plugin Design)
	LLM07SystemPromptLeakage     OWASPLLM = "LLM07" // System Prompt Leakage (new in 2025)
	LLM08VectorEmbedding         OWASPLLM = "LLM08" // Vector and Embedding Weaknesses (new in 2025)
	LLM09Misinformation          OWASPLLM = "LLM09" // Misinformation (2023 LLM09 Overreliance)
	LLM10UnboundedConsumption    OWASPLLM = "LLM10" // Unbounded Consumption (2023 LLM04 Model Denial of Service)
)

// owaspLLMInfo holds the immutable metadata for each category.
type owaspLLMInfo struct {
	title string
	slug  string // path segment under genai.owasp.org/llmrisk/
}

var owaspLLMCatalog = map[OWASPLLM]owaspLLMInfo{
	LLM01PromptInjection:         {"Prompt Injection", "llm01-prompt-injection"},
	LLM02SensitiveInfoDisclosure: {"Sensitive Information Disclosure", "llm02-sensitive-information-disclosure"},
	LLM03SupplyChain:             {"Supply Chain", "llm03-supply-chain"},
	LLM04DataModelPoisoning:      {"Data and Model Poisoning", "llm04-data-and-model-poisoning"},
	LLM05ImproperOutputHandling:  {"Improper Output Handling", "llm05-improper-output-handling"},
	LLM06ExcessiveAgency:         {"Excessive Agency", "llm06-excessive-agency"},
	LLM07SystemPromptLeakage:     {"System Prompt Leakage", "llm07-system-prompt-leakage"},
	LLM08VectorEmbedding:         {"Vector and Embedding Weaknesses", "llm08-vector-and-embedding-weaknesses"},
	LLM09Misinformation:          {"Misinformation", "llm09-misinformation"},
	LLM10UnboundedConsumption:    {"Unbounded Consumption", "llm10-unbounded-consumption"},
}

// allOWASPLLM is the canonical ordered list (LLM01..LLM10).
var allOWASPLLM = []OWASPLLM{
	LLM01PromptInjection,
	LLM02SensitiveInfoDisclosure,
	LLM03SupplyChain,
	LLM04DataModelPoisoning,
	LLM05ImproperOutputHandling,
	LLM06ExcessiveAgency,
	LLM07SystemPromptLeakage,
	LLM08VectorEmbedding,
	LLM09Misinformation,
	LLM10UnboundedConsumption,
}

// Valid reports whether c is one of the ten known 2025 categories.
func (c OWASPLLM) Valid() bool {
	_, ok := owaspLLMCatalog[c]
	return ok
}

// Title returns the human-readable category name (empty for an unknown code).
func (c OWASPLLM) Title() string {
	return owaspLLMCatalog[c].title
}

// Reference returns the canonical OWASP GenAI URL for the category (empty for
// an unknown code).
func (c OWASPLLM) Reference() string {
	info, ok := owaspLLMCatalog[c]
	if !ok {
		return ""
	}
	return "https://genai.owasp.org/llmrisk/" + info.slug + "/"
}

// Tag returns the lowercase kebab finding tag for the category, e.g.
// "owasp-llm02". Deriving the tag from the constant keeps the two in lockstep:
// a rule tagged via LLM02SensitiveInfoDisclosure.Tag() cannot silently drift
// from the category it claims to model.
func (c OWASPLLM) Tag() string {
	return "owasp-" + strings.ToLower(string(c))
}

// LLMTag is a convenience wrapper around (OWASPLLM).Tag for call sites that
// prefer a function form.
func LLMTag(c OWASPLLM) string { return c.Tag() }

// AllOWASPLLM returns the ten categories in canonical order (LLM01..LLM10).
func AllOWASPLLM() []OWASPLLM {
	out := make([]OWASPLLM, len(allOWASPLLM))
	copy(out, allOWASPLLM)
	return out
}
