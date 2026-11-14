package deps

import (
	"bytes"
	"encoding/json"
	"path"
	"strconv"
	"strings"
)

// A multi-stage Dockerfile ships only its final stage. An image named by an
// earlier FROM is a build environment: its packages are in the image that is
// published only if the final stage is built on that stage, or copies the
// stage's system files across. nox's own Dockerfile builds a static Go binary
// on golang:1.27-alpine and copies that one file onto distroless; a zlib
// advisory in the Alpine builder was reported at the rating of a zlib in the
// shipped image, which it never is.
//
// Docker builds the final stage unless told otherwise (`--target`). A target
// is named outside the Dockerfile, so a stage the Dockerfile does not ship can
// still be built and published on its own; the finding says which stage it
// was, so a reader who builds with --target knows to read it as shipped.

// buildOnlyStages returns, index-aligned with ParseDockerfile's packages, the
// name of the build stage each image belongs to when that stage does not reach
// the final image, and "" when it does or when that cannot be told. Anything
// this parser cannot resolve — a FROM or COPY --from naming a variable, a stage
// it cannot find — makes every stage count as shipped: the cost of a wrong
// "build-only" is a real advisory recorded at info.
func buildOnlyStages(content []byte) []string {
	type copyFrom struct {
		from string
		srcs []string
	}
	type stage struct {
		name     string // the AS alias, or the stage's index
		base     int    // index of the stage this one is built FROM, or -1
		imageIdx int    // index into ParseDockerfile's packages, or -1
		copies   []copyFrom
	}

	var stages []stage
	byName := map[string]int{}  // alias or index -> stage, for COPY --from
	aliases := map[string]int{} // alias -> stage, for FROM <stage>, as ParseDockerfile reads it
	unresolved := false
	images := 0

	scanner := newLineScanner(bytes.NewReader(content))
	var pending strings.Builder
	instruction := func(line string) {
		if len(stages) == 0 {
			return
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.EqualFold(fields[0], "COPY") {
			return
		}
		from, srcs, ok := parseCopyFrom(line)
		if !ok {
			return
		}
		if strings.Contains(from, "$") {
			unresolved = true
			return
		}
		cur := &stages[len(stages)-1]
		cur.copies = append(cur.copies, copyFrom{from: from, srcs: srcs})
	}
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if pending.Len() > 0 {
			pending.WriteByte(' ')
			pending.WriteString(strings.TrimSuffix(trimmed, `\`))
			if !strings.HasSuffix(trimmed, `\`) {
				instruction(pending.String())
				pending.Reset()
			}
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := reFromInstruction.FindStringSubmatch(trimmed); m != nil {
			ref, alias := m[1], strings.ToLower(m[2])
			cur := len(stages)
			s := stage{name: strconv.Itoa(cur), base: -1, imageIdx: -1}
			// Registered before the reference is judged, as ParseDockerfile
			// does: the two must skip exactly the same FROMs, or every later
			// finding is attributed to the wrong image.
			if alias != "" {
				s.name = alias
				aliases[alias] = cur
			}
			switch {
			case skipImageRef(ref, aliasSet(aliases)):
				if idx, ok := aliases[strings.ToLower(ref)]; ok && idx != cur {
					s.base = idx
				} else if strings.Contains(ref, "$") {
					unresolved = true
				}
			default:
				if name, _ := parseImageRef(ref); name != "" {
					s.imageIdx = images
					images++
				}
			}
			byName[s.name] = cur
			byName[strconv.Itoa(cur)] = cur
			stages = append(stages, s)
			continue
		}
		if strings.HasSuffix(trimmed, `\`) {
			pending.WriteString(strings.TrimSuffix(trimmed, `\`))
			continue
		}
		instruction(trimmed)
	}

	out := make([]string, images)
	if len(stages) == 0 || unresolved || scanner.Err() != nil {
		return out
	}

	shipped := make([]bool, len(stages))
	work := []int{len(stages) - 1}
	for len(work) > 0 {
		i := work[len(work)-1]
		work = work[:len(work)-1]
		if shipped[i] {
			continue
		}
		shipped[i] = true
		if b := stages[i].base; b >= 0 {
			work = append(work, b)
		}
		for _, c := range stages[i].copies {
			src, isStage := byName[strings.ToLower(c.from)]
			if !isStage {
				// COPY --from an image, not a stage of this build: that image's
				// files are not this Dockerfile's FROM images.
				continue
			}
			if copiesSystemFiles(c.srcs) {
				work = append(work, src)
			}
		}
	}
	for i, s := range stages {
		if s.imageIdx >= 0 && !shipped[i] {
			out[s.imageIdx] = s.name
		}
	}
	return out
}

func aliasSet(aliases map[string]int) map[string]bool {
	set := make(map[string]bool, len(aliases))
	for a := range aliases {
		set[a] = true
	}
	return set
}

// parseCopyFrom reads a COPY instruction's --from value and its source paths
// (every argument but the last, in either the shell or the JSON form). ok is
// false when the instruction has no --from.
func parseCopyFrom(line string) (from string, srcs []string, ok bool) {
	rest := strings.TrimSpace(line[len("COPY"):])
	for strings.HasPrefix(rest, "--") {
		flag, tail, _ := strings.Cut(rest, " ")
		if v, found := strings.CutPrefix(flag, "--from="); found {
			from, ok = v, true
		}
		rest = strings.TrimSpace(tail)
	}
	if !ok {
		return "", nil, false
	}
	var args []string
	if strings.HasPrefix(rest, "[") {
		if err := json.Unmarshal([]byte(rest), &args); err != nil {
			// Unreadable: count it as copying everything.
			return from, []string{"/"}, true
		}
	} else {
		args = strings.Fields(rest)
	}
	if len(args) < 2 {
		return from, []string{"/"}, true
	}
	return from, args[:len(args)-1], true
}

// systemRoots are where a distribution's package manager installs, and where
// nox reads a base image's packages from (lib/apk/db, var/lib/dpkg,
// var/lib/rpm, usr/local/go). A COPY --from that takes anything under them can
// carry a build stage's packages into the shipped image.
var systemRoots = []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32", "usr", "etc", "var", "opt"}

// copiesSystemFiles reports whether any source of a COPY --from may hold an
// installed package's files. A COPY --from source is read from the root of
// the stage it names, so a relative path is a path from /. A variable or a
// wildcard in the first path segment could be anything.
func copiesSystemFiles(srcs []string) bool {
	for _, s := range srcs {
		if strings.Contains(s, "$") {
			return true
		}
		p := strings.TrimPrefix(path.Clean("/"+s), "/")
		if p == "" || p == "." {
			return true
		}
		first, _, _ := strings.Cut(p, "/")
		if strings.ContainsAny(first, "*?[") {
			return true
		}
		for _, root := range systemRoots {
			if first == root {
				return true
			}
		}
	}
	return false
}
