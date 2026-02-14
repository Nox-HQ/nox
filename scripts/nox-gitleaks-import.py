#!/usr/bin/env python3
"""Convert Gitleaks rules to Nox format."""

import re


def parse_gitleaks(content):
    """Parse Gitleaks TOML and extract rules."""
    rules = []

    # Split by [[rules]] and process each block
    parts = content.split("[[rules]]")

    for block in parts[1:]:  # Skip first part (before first [[rules]])
        if not block.strip():
            continue

        # Extract fields
        id_match = re.search(r'id\s*=\s*"([^"]+)"', block)
        if not id_match:
            continue
        rule_id = id_match.group(1)

        desc_match = re.search(r'description\s*=\s*"([^"]+)"', block)
        description = desc_match.group(1) if desc_match else ""

        # Handle triple-quoted regex - try both ''' and """
        # Triple single quotes are most common in Gitleaks
        regex_match = re.search(r"regex\s*=\s*'''(.+?)'''", block)
        if not regex_match:
            regex_match = re.search(r'regex\s*=\s*"""(.+?)"""', block)
        if not regex_match:
            regex_match = re.search(r'regex\s*=\s*"([^"]+)"', block)
        regex_pattern = regex_match.group(1) if regex_match else ""

        # Keywords
        keywords = []
        kw_match = re.search(r"keywords\s*=\s*\[([^\]]+)\]", block)
        if kw_match:
            keywords = re.findall(r'"([^"]+)"', kw_match.group(1))

        # Entropy
        entropy = 0.0
        ent_match = re.search(r"entropy\s*=\s*([\d.]+)", block)
        if ent_match:
            entropy = float(ent_match.group(1))

        if regex_pattern:
            rules.append(
                {
                    "id": rule_id,
                    "description": description,
                    "regex": regex_pattern,
                    "keywords": keywords,
                    "entropy": entropy,
                }
            )

    return rules


EXISTING_RULES = {
    "1password-secret-key",
    "1password-service-account-token",
    "adafruit-api-key",
    "adobe-client-id",
    "adobe-client-secret",
    "age-secret-key",
    "airtable-api-key",
    "alibaba-access-key-id",
    "alibaba-secret-key",
    "anthropic-api-key",
    "artifactory-api-key",
    "asana-client-id",
    "asana-client-secret",
    "atlassian-api-token",
    "aws-access-token",
    "azure-ad-client-secret",
    "bitbucket-client-id",
    "cloudflare-api-key",
    "codecov-access-token",
    "cohere-api-token",
    "confluent-access-token",
    "databricks-api-token",
    "datadog-access-token",
    "digitalocean-access-token",
    "discord-api-token",
    "discord-client-id",
    "dropbox-api-token",
    "fastly-api-token",
    "gcp-api-key",
    "generic-api-key",
    "github-token",
    "gitlab-token",
    "slack-token",
    "stripe-api-key",
    "twilio-api-key",
}


def main():
    with open("/tmp/gitleaks.toml", "r") as f:
        content = f.read()

    rules = parse_gitleaks(content)
    print(f"Parsed {len(rules)} rules from Gitleaks\n")

    # Show first 10
    print("=== Sample Rules (first 10) ===")
    for r in rules[:10]:
        print(f"- {r['id']}: {r['description'][:50]}...")
        print(f"  Regex: {r['regex'][:60]}...")
        if r["keywords"]:
            print(f"  Keywords: {r['keywords'][:3]}...")
        print()

    # Generate Nox rules
    print("\n=== Ready to copy to rules.go ===\n")
    sec_num = 163

    for r in rules:
        if r["id"] in EXISTING_RULES:
            continue

        sec_num += 1
        rule_id = f"SEC-{sec_num:03d}"

        # Determine severity
        severity = "findings.SeverityHigh"
        if r["entropy"] > 4.5:
            severity = "findings.SeverityMedium"

        # Format keywords
        if r["keywords"]:
            kw_str = "[]string{" + ", ".join(f'"{k}"' for k in r["keywords"]) + "}"
        else:
            kw_str = "nil"

        # Escape description
        desc = r["description"].replace('"', '\\"').replace("\n", " ")

        print(f"\t\t// {rule_id} (from Gitleaks: {r['id']})")
        print(f"\t\t{{{rule_id}, {severity}, findings.ConfidenceMedium,")
        print(f"\t\t\tpattern: `{r['regex']}`,")
        print(f'\t\t\tdescription: "{desc}",')
        print(f"\t\t\tkeywords: {kw_str},")
        print(f'\t\t\tremediation: "Imported from Gitleaks: {r["id"]}",')
        print("\t\t\treferences: []string{},")
        print("\t\t},")


if __name__ == "__main__":
    main()
