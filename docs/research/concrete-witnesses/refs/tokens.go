package refs

import (
	"fmt"
	"math/rand"
	"strings"
)

// --- GitHub classic tokens -------------------------------------------------

// githubClaims are the rules whose DESCRIPTION claims a GitHub token of these
// shapes, read from the built rule dump. The first version of this list was
// taken from rule patterns and missed SEC-017 and SEC-217, which then showed
// up as "another rule reported it": a claim list is part of the model.
// Fine-grained github_pat_ rules are excluded; that format is not modelled.
var githubClaims = []string{"SEC-003", "SEC-017", "SEC-213", "SEC-215", "SEC-216", "SEC-217", "SEC-435", "SEC-495", "SEC-496", "SEC-497"}

// GitHubClassic models only what GitHub publishes. The checksum is NOT in the
// model: GitHub documents that one exists ("a 32 bit checksum in the last 6
// digits ... CRC32 ... Base62"), but not whether the prefix is hashed nor the
// digit order, and no real revoked token was found to settle either. A
// checksum constraint written from inference would be a guess presented as a
// specification.
var GitHubClassic = Format{
	Name:        "github-classic",
	Proposition: "x is a GitHub classic-format token (ghp_, gho_, ghu_, ghs_ legacy, ghr_)",
	Sources: []Source{
		{"https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/", "the five prefixes and the _ separator (documented); 30 random [a-zA-Z0-9] characters (from its entropy formula) plus a 6-digit checksum"},
		{"https://github.blog/changelog/ (2026-04-24, ghs_ stateless rollout)", "the regex ghs_[A-Za-z0-9]{36} given as the legacy shape (by example)"},
	},
	Claims: githubClaims,
	Hosts:  tokenHosts,
	Check: func(s string) string {
		if len(s) < 4 || !oneOf(s[:4], "ghp_", "gho_", "ghu_", "ghs_", "ghr_") {
			return "prefix"
		}
		if len(s) != 40 {
			return "length"
		}
		if !allIn(s[4:], alnum) {
			return "alphabet"
		}
		return ""
	},
	Valid: func(r *rand.Rand) []Named {
		var out []Named
		for _, p := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"} {
			out = append(out, Named{"legacy-" + strings.TrimSuffix(p, "_"), p + randFrom(r, alnum, 36)})
		}
		return out
	},
	Mutate: func(r *rand.Rand, v string) []Named {
		return append(tokenMutants(r, v, alnum),
			Named{"underscore-in-body", v[:20] + "_" + v[21:]},
			Named{"uppercase-prefix", strings.ToUpper(v[:3]) + v[3:]},
		)
	},
	Limits: []string{
		"checksum excluded: its input and digit order are undocumented",
		"length 40 is by example only; GitHub reserves up to 255",
	},
}

// GitHubStateless is the ghs_ installation-token format GitHub rolled out from
// 2026-04-27: ghs_<APPID>_<JWT>, ~520 characters and variable.
var GitHubStateless = Format{
	Name:        "github-ghs-stateless",
	Proposition: "x is a GitHub App installation token in the stateless ghs_APPID_JWT format",
	Sources: []Source{
		{"https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github", "\"a stateless format ( ghs_APPID_JWT )\", staged rollout from 2026-04-27"},
		{"https://github.blog/changelog/ (2026-04-24)", "\"longer (~520 characters) and will vary\""},
	},
	Claims: githubClaims,
	Hosts:  tokenHosts,
	Check: func(s string) string {
		if !strings.HasPrefix(s, "ghs_") {
			return "prefix"
		}
		rest := s[4:]
		i := strings.IndexByte(rest, '_')
		if i < 1 || !allIn(rest[:i], "0123456789") {
			return "appid"
		}
		if v := jwsViolation(rest[i+1:]); v != "" {
			return "jwt:" + v
		}
		return ""
	},
	Valid: func(r *rand.Rand) []Named {
		appID := fmt.Sprint(100000 + r.Intn(9000000))
		return []Named{
			{"ghs-stateless-rs256", "ghs_" + appID + "_" + makeJWS(r, `{"alg":"RS256","typ":"JWT"}`, randomClaims(r, 6), 256)},
		}
	},
	Mutate: func(r *rand.Rand, v string) []Named {
		return []Named{{"glued-left-alnum", "x" + v}}
	},
	Limits: []string{"APPID assumed decimal: GitHub App IDs are integers, but the token page does not say how it is written"},
}

// --- AWS access key IDs ----------------------------------------------------

var awsKeyPrefixes = []string{"AKIA", "ASIA", "ABIA", "ACCA"}

// AWSAccessKeyID is deliberately as loose as AWS's documentation, which is the
// point of including it: the published constraints are a prefix table and the
// IAM API's "Length 16-128, Pattern [\w]+". The base32 alphabet every real
// key is observed to use is not published anywhere AWS was found to say so.
var AWSAccessKeyID = Format{
	Name:        "aws-access-key-id",
	Proposition: "x is an AWS access key ID",
	Sources: []Source{
		{"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html", "prefixes ABIA, ACCA, AKIA, ASIA (documented); \"Prefixes may vary\""},
		{"https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKey.html", "AccessKeyId: length 16-128, pattern [\\w]+"},
	},
	Claims: []string{"SEC-001", "SEC-508", "SEC-509"},
	Hosts: append(tokenHosts,
		linePrefix("aws-credentials-file", "ini", "[default]\naws_access_key_id = ", "\n")),
	Check: func(s string) string {
		if len(s) < 4 || !oneOf(s[:4], awsKeyPrefixes...) {
			return "prefix"
		}
		if len(s) < 16 || len(s) > 128 {
			return "length"
		}
		if !allIn(s, alnum+"_") {
			return "alphabet"
		}
		return ""
	},
	Valid: func(r *rand.Rand) []Named {
		const b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
		var out []Named
		for _, p := range awsKeyPrefixes {
			out = append(out, Named{"observed-shape-" + p, p + randFrom(r, b32, 16)})
		}
		out = append(out,
			Named{"documented-only-digits0189", "AKIA" + randFrom(r, b32, 12) + "0189"},
			Named{"documented-only-lowercase", "AKIA" + strings.ToLower(randFrom(r, b32, 16))},
			Named{"documented-only-len24", "AKIA" + randFrom(r, b32, 20)},
		)
		return out
	},
	Mutate: func(r *rand.Rand, v string) []Named { return tokenMutants(r, v, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") },
	Limits: []string{"alphabet and length are the API's, far looser than any issued key: FN witnesses outside the observed shape are artefacts of an under-specified source"},
}

// --- Twilio API key SID ----------------------------------------------------

var TwilioAPIKeySID = Format{
	Name:        "twilio-api-key-sid",
	Proposition: "x is a Twilio API Key SID",
	Sources: []Source{
		{"https://www.twilio.com/docs/glossary/what-is-a-sid", "\"34-character ... two-letter prefix followed by 32 hexadecimal digits\"; SK = API Key"},
	},
	Claims: []string{"SEC-057"},
	Hosts: append(tokenHosts,
		linePrefix("dotenv", "env", "TWILIO_API_KEY=", "\n")),
	Check: func(s string) string {
		if !strings.HasPrefix(s, "SK") {
			return "prefix"
		}
		if len(s) != 34 {
			return "length"
		}
		if !allIn(s[2:], hexDigits) {
			return "alphabet"
		}
		return ""
	},
	Valid: func(r *rand.Rand) []Named {
		return []Named{
			{"lowercase-hex", "SK" + randFrom(r, "0123456789abcdef", 32)},
			{"uppercase-hex", "SK" + randFrom(r, "0123456789ABCDEF", 32)},
		}
	},
	Mutate: func(r *rand.Rand, v string) []Named {
		return append(tokenMutants(r, v, "0123456789abcdef"),
			Named{"glued-left-word", "TASK" + v[2:]},
			Named{"inside-longer-hex", "DISK" + v[2:] + randFrom(r, "0123456789abcdef", 8)},
		)
	},
	Limits: []string{"hex case is undocumented; both cases are accepted"},
}

// --- AWS SNS topic ARN -----------------------------------------------------

var awsPartitions = []string{"aws", "aws-cn", "aws-us-gov"}

var SNSTopicARN = Format{
	Name:        "aws-sns-topic-arn",
	Proposition: "x is an AWS SNS topic ARN (a resource identifier; the rule says it is not a credential)",
	Sources: []Source{
		{"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html", "arn:partition:service:region:account-id:resource-id; partitions aws, aws-cn, aws-us-gov"},
		{"https://docs.aws.amazon.com/sns/latest/api/API_CreateTopic.html", "topic name: ASCII letters, digits, _ and -, 1-256 characters; FIFO names end in .fifo"},
	},
	Claims: []string{"SEC-519"},
	Hosts: []Host{
		HostPyQuoted,
		linePrefix("py-quoted-aws_sns-name", "py", `aws_sns_topic = "`, "\"\n"),
	},
	Check: func(s string) string {
		p := strings.SplitN(s, ":", 6)
		if len(p) != 6 || p[0] != "arn" {
			return "arn-shape"
		}
		if !oneOf(p[1], awsPartitions...) {
			return "partition"
		}
		if p[2] != "sns" {
			return "service"
		}
		if p[3] == "" || !allIn(p[3], "abcdefghijklmnopqrstuvwxyz0123456789-") {
			return "region"
		}
		if len(p[4]) != 12 || !allIn(p[4], "0123456789") {
			return "account"
		}
		name := strings.TrimSuffix(p[5], ".fifo")
		if len(name) < 1 || len(name) > 256 || !allIn(name, alnum+"_-") {
			return "topic-name"
		}
		return ""
	},
	Valid: func(r *rand.Rand) []Named {
		acct := randFrom(r, "0123456789", 12)
		return []Named{
			{"partition-aws", "arn:aws:sns:us-east-2:" + acct + ":Orders-" + randFrom(r, alnum, 6)},
			{"partition-aws-cn", "arn:aws-cn:sns:cn-north-1:" + acct + ":orders"},
			{"partition-aws-us-gov", "arn:aws-us-gov:sns:us-gov-west-1:" + acct + ":alerts"},
			{"fifo-topic", "arn:aws:sns:eu-west-1:" + acct + ":events.fifo"},
		}
	},
	Mutate: func(r *rand.Rand, v string) []Named {
		return []Named{
			{"prefix-only", "arn:aws:sns:"},
			{"account-11-digits", strings.Replace(v, v[strings.LastIndex(v, ":")-12:strings.LastIndex(v, ":")], "12345678901", 1)},
		}
	},
	Limits: []string{"region syntax is not validated against the region list", "partitions beyond the three documented ones exist in AWS SDK data and are excluded"},
}

func oneOf(s string, set ...string) bool {
	for _, x := range set {
		if s == x {
			return true
		}
	}
	return false
}
