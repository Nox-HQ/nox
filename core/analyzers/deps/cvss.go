package deps

import (
	"math"
	"strings"
)

// cvssV3BaseScore computes the CVSS v3.0/v3.1 base score from a vector string.
//
// OSV publishes severity as vector strings ("CVSS:3.1/AV:N/AC:L/...") rather
// than numeric scores, so a scanner that only parses floats sees no severity at
// all and falls back to a default. The base score is fully determined by the
// vector, so it can be computed offline — no lookup required.
//
// Implements the formulas in the CVSS v3.1 specification, section 8.1:
// https://www.first.org/cvss/v3.1/specification-document
func cvssV3BaseScore(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0, false
	}

	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/")[1:] {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		metrics[k] = v
	}

	scopeChanged := metrics["S"] == "C"

	av, ok := lookupCVSS(metrics, "AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if !ok {
		return 0, false
	}
	ac, ok := lookupCVSS(metrics, "AC", map[string]float64{"L": 0.77, "H": 0.44})
	if !ok {
		return 0, false
	}
	// Privileges Required is weighted differently when scope changes.
	prWeights := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scopeChanged {
		prWeights = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	}
	pr, ok := lookupCVSS(metrics, "PR", prWeights)
	if !ok {
		return 0, false
	}
	ui, ok := lookupCVSS(metrics, "UI", map[string]float64{"N": 0.85, "R": 0.62})
	if !ok {
		return 0, false
	}

	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, ok := lookupCVSS(metrics, "C", cia)
	if !ok {
		return 0, false
	}
	i, ok := lookupCVSS(metrics, "I", cia)
	if !ok {
		return 0, false
	}
	a, ok := lookupCVSS(metrics, "A", cia)
	if !ok {
		return 0, false
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))

	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui

	score := impact + exploitability
	if scopeChanged {
		score = 1.08 * score
	}
	return cvssRoundUp(math.Min(score, 10)), true
}

// lookupCVSS resolves one metric to its numeric weight.
func lookupCVSS(metrics map[string]string, key string, weights map[string]float64) (float64, bool) {
	v, present := metrics[key]
	if !present {
		return 0, false
	}
	w, known := weights[v]
	return w, known
}

// cvssRoundUp rounds up to one decimal place using the integer arithmetic the
// CVSS v3.1 spec mandates (appendix A) — plain math.Ceil on a float misrounds
// values that are only imprecise through binary representation.
func cvssRoundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000.0
	}
	return (math.Floor(float64(i)/10000) + 1) / 10.0
}
