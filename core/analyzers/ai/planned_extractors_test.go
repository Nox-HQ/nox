package ai

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/rules"
)

// The extractor patterns run over every AI-flavoured source file. Those that
// are case-insensitive or open with an alternation cannot be sped up by
// regexp, so they go through the literal-prefix plan; a pattern edited out of
// its plan would quietly read every byte of every such file again (#736).
// Each must also return what plain regexp returns.
func TestExtractorPatternsArePlannedAndExact(t *testing.T) {
	planned := map[string]*rules.PlannedRegexp{
		"promptSystem":      promptSystemRe,
		"promptTemplate":    promptTemplateRe,
		"promptRoleContent": promptRoleContentRe,
		"promptRole":        promptRoleRe,
		"modelFromPretrain": modelFromPretrainedRe,
		"modelConfig":       modelConfigRe,
		"toolList":          toolListRe,
		"sdk openai":        providerInvocations[0].re,
		"sdk google":        providerInvocations[2].re,
	}
	corpus := []string{
		"", `system_prompt = "You are {role}."`, `SYSTEM_MESSAGE: f"hi {x}"`,
		`ChatPromptTemplate.from_messages([`, `prompttemplate . from_template(`,
		`{"role": "system", "content": "be terse"}`, `{'ROLE':'user'}`,
		`AutoModelForCausalLM.from_pretrained("meta-llama/Llama-3", revision="abc")`,
		`pipeline("text-generation")`, `model: "gpt-4o"`, `MODEL_ID = 'claude-3'`,
		`allowed_tools: ["shell", "fetch"]`, `client.chat.completions.create(model="gpt-4o")`,
		`genai.GenerativeModel("gemini-1.5-pro")`, "Key = 1", "ſystem_prompt = 'x'",
		strings.Repeat("model = x\n", 40) + `model="m"`, "\xff\"role\": \"assistant\"",
	}
	for name, p := range planned {
		if !p.HasPlan() {
			t.Errorf("%s: pattern %q has no literal-prefix plan", name, p)
		}
		re := regexp.MustCompile(p.String())
		for _, c := range corpus {
			if got, want := p.FindAllSubmatchIndex([]byte(c)), re.FindAllSubmatchIndex([]byte(c), -1); !reflect.DeepEqual(got, want) {
				t.Errorf("%s on %q: %v, regexp says %v", name, c, got, want)
			}
		}
	}
}

// stringSubmatches must give what FindAllStringSubmatch gives, a group that
// took no part included.
func TestStringSubmatchesAgreesWithRegexp(t *testing.T) {
	re := regexp.MustCompile(`(a)(x)?(b)`)
	for _, text := range []string{"", "ab", "axb ab", "zzz", "abab"} {
		got := stringSubmatches(text, re.FindAllStringSubmatchIndex(text, -1))
		want := re.FindAllStringSubmatch(text, -1)
		if len(got) == 0 && len(want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %q, regexp says %q", text, got, want)
		}
	}
}
