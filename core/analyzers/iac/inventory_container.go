package iac

import (
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nox-hq/nox/core/infra"
	"github.com/nox-hq/nox/core/rules/structural"
)

// ---- Dockerfile ---------------------------------------------------------------

var (
	dockerFromRe = regexp.MustCompile(`(?i)^FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?`)
	dockerUserRe = regexp.MustCompile(`(?i)^USER\s+(\S+)`)
	dockerEnvRe  = regexp.MustCompile(`(?i)^ENV\s+(.*)$`)
)

type dockerStage struct {
	base    string
	alias   string
	user    string
	line    int
	env     map[string]string
	hasFrom bool
}

// dockerfileResources describes the image a Dockerfile builds: the final stage,
// which is what ships. An earlier stage's USER or base does not reach it.
func dockerfileResources(path string, content []byte) []infra.Resource {
	lines := logicalLines(string(content))
	var stages []*dockerStage
	var cur *dockerStage
	for _, l := range lines {
		text := strings.TrimSpace(l.text)
		if m := dockerFromRe.FindStringSubmatch(text); m != nil {
			cur = &dockerStage{base: m[1], alias: m[2], line: l.line, env: map[string]string{}, hasFrom: true}
			stages = append(stages, cur)
			continue
		}
		if cur == nil {
			continue
		}
		if m := dockerUserRe.FindStringSubmatch(text); m != nil {
			cur.user = m[1]
		}
		if m := dockerEnvRe.FindStringSubmatch(text); m != nil {
			for k, v := range dockerEnvPairs(m[1]) {
				cur.env[k] = v
			}
		}
	}
	if len(stages) == 0 {
		return nil
	}
	final := stages[len(stages)-1]
	r := infra.Resource{
		Kind: "Dockerfile", Name: filepath.Base(path), File: path, Class: infra.ClassImage,
		Line: final.line, EndLine: lines[len(lines)-1].line, Properties: map[string]string{},
	}
	r.Properties["image_pin"] = pinOf(resolveStageBase(stages, final))
	r.Properties["user"] = dockerUser(stages, final)
	for name, v := range final.env {
		if isCredentialName(name) {
			setEnv(&r, name, literalSource(v))
		}
	}
	return []infra.Resource{r}
}

// resolveStageBase follows `FROM build AS final` back to the image it names.
func resolveStageBase(stages []*dockerStage, s *dockerStage) string {
	base := s.base
	for i := len(stages) - 1; i >= 0; i-- {
		if stages[i] != s && stages[i].alias != "" && strings.EqualFold(stages[i].alias, base) {
			return resolveStageBase(stages[:i+1], stages[i])
		}
	}
	return base
}

// dockerUser is the user the final image runs as. A stage that starts FROM
// another stage inherits its USER.
func dockerUser(stages []*dockerStage, s *dockerStage) string {
	if s.user != "" {
		return userValue(s.user)
	}
	for i := len(stages) - 1; i >= 0; i-- {
		if stages[i] != s && stages[i].alias != "" && strings.EqualFold(stages[i].alias, s.base) {
			return dockerUser(stages[:i+1], stages[i])
		}
	}
	return "root (no USER)"
}

func userValue(u string) string {
	switch {
	case strings.ContainsAny(u, "$"):
		return infra.Dynamic
	case u == "root" || u == "0" || strings.HasPrefix(u, "root:") || strings.HasPrefix(u, "0:"):
		return "root"
	}
	return u
}

type logicalLine struct {
	text string
	line int
}

// logicalLines joins backslash continuations and drops comments and blank
// lines, keeping the line each statement starts on.
func logicalLines(src string) []logicalLine {
	var out []logicalLine
	var buf strings.Builder
	start := 0
	for i, raw := range strings.Split(src, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if buf.Len() == 0 && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			continue
		}
		if buf.Len() == 0 {
			start = i + 1
		}
		if strings.HasSuffix(trimmed, "\\") {
			buf.WriteString(strings.TrimSuffix(trimmed, "\\") + " ")
			continue
		}
		buf.WriteString(trimmed)
		out = append(out, logicalLine{text: buf.String(), line: start})
		buf.Reset()
	}
	if buf.Len() > 0 {
		out = append(out, logicalLine{text: buf.String(), line: start})
	}
	if len(out) == 0 {
		out = append(out, logicalLine{line: 1})
	}
	return out
}

// dockerEnvPairs reads `ENV A=1 B=2` and `ENV A 1`.
func dockerEnvPairs(s string) map[string]string {
	out := map[string]string{}
	s = strings.TrimSpace(s)
	if !strings.Contains(strings.Fields(s + " x")[0], "=") {
		name, value, _ := strings.Cut(s, " ")
		out[name] = strings.Trim(strings.TrimSpace(value), `"'`)
		return out
	}
	for _, f := range strings.Fields(s) {
		if k, v, ok := strings.Cut(f, "="); ok {
			out[k] = strings.Trim(v, `"'`)
		}
	}
	return out
}

// ---- Compose ------------------------------------------------------------------

func composeResources(path string, content []byte) []infra.Resource {
	docs, err := structural.Parse(content)
	if err != nil {
		return nil
	}
	var out []infra.Resource
	for _, doc := range docs {
		services := mappingValue(doc, "services")
		if services == nil || services.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(services.Content); i += 2 {
			name, spec := services.Content[i], services.Content[i+1]
			if spec.Kind != yaml.MappingNode {
				continue
			}
			r := infra.Resource{
				Kind: "compose_service", Name: name.Value, File: path, Class: infra.ClassWorkload,
				Line: name.Line, EndLine: maxLine(spec), Properties: map[string]string{},
			}
			composeProperties(&r, spec)
			out = append(out, r)
		}
	}
	return out
}

func composeProperties(r *infra.Resource, spec *yaml.Node) {
	if image := mapChild(spec, "image"); image != nil {
		r.Properties["image_pin"] = pinOf(scalar(image))
	}
	r.Properties["privileged"] = boolProp(mapChild(spec, "privileged"), "false")
	hostNet := "false"
	if scalar(mapChild(spec, "network_mode")) == "host" {
		hostNet = "true"
	}
	r.Properties["host_network"] = hostNet
	hostPID := "false"
	if scalar(mapChild(spec, "pid")) == "host" {
		hostPID = "true"
	}
	r.Properties["host_pid"] = hostPID
	if u := scalar(mapChild(spec, "user")); u != "" {
		r.Properties["user"] = userValue(u)
	} else {
		r.Properties["user"] = "root (no user)"
	}
	r.Properties["capabilities_added"] = capabilitySummary(seqItems(mapChild(spec, "cap_add")))
	composeEnv(r, mapChild(spec, "environment"))
}

// composeEnv reads the map and the list form of `environment`.
func composeEnv(r *infra.Resource, env *yaml.Node) {
	if env == nil {
		return
	}
	switch env.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(env.Content); i += 2 {
			if name := env.Content[i].Value; isCredentialName(name) {
				setEnv(r, name, literalSource(scalar(env.Content[i+1])))
			}
		}
	case yaml.SequenceNode:
		for _, item := range env.Content {
			name, value, ok := strings.Cut(scalar(item), "=")
			if ok && isCredentialName(name) {
				setEnv(r, name, literalSource(value))
			}
		}
	}
}
