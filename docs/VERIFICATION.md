# Verifying Nox Releases

Nox releases are signed using [Sigstore cosign](https://github.com/sigstore/cosign) (keyless mode) and include [SLSA Level 3 provenance](https://slsa.dev/) attestations.

## Prerequisites

Install cosign:

```bash
# macOS
brew install cosign

# Linux
go install github.com/sigstore/cosign/v2/cmd/cosign@latest
```

Install the SLSA verifier:

```bash
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
```

## Verifying Binary Checksums

Each release includes `checksums.txt`, `checksums.txt.sig` (signature), and `checksums.txt.pem` (certificate).

```bash
# Download release artifacts
VERSION=0.7.0
gh release download "v${VERSION}" --repo nox-hq/nox \
  --pattern 'checksums.txt*' --dir /tmp/nox-verify

# Verify the signature
cosign verify-blob /tmp/nox-verify/checksums.txt \
  --signature /tmp/nox-verify/checksums.txt.sig \
  --certificate /tmp/nox-verify/checksums.txt.pem \
  --certificate-identity-regexp 'https://github.com/nox-hq/nox/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Then verify your downloaded archive against the checksums:

```bash
# Verify archive checksum
sha256sum -c /tmp/nox-verify/checksums.txt --ignore-missing
```

## Verifying Docker Images

Docker images pushed to `ghcr.io/nox-hq/nox` are signed with cosign.

```bash
# Verify the Docker image signature
cosign verify ghcr.io/nox-hq/nox:latest \
  --certificate-identity-regexp 'https://github.com/nox-hq/nox/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

## Verifying SLSA Provenance

SLSA provenance attestations are attached to each release.

```bash
# Download the provenance file
gh release download "v${VERSION}" --repo nox-hq/nox \
  --pattern '*.intoto.jsonl' --dir /tmp/nox-verify

# Verify provenance
slsa-verifier verify-artifact /tmp/nox-verify/nox_${VERSION}_linux_amd64.tar.gz \
  --provenance-path /tmp/nox-verify/multiple.intoto.jsonl \
  --source-uri github.com/nox-hq/nox \
  --source-tag "v${VERSION}"
```

## What This Guarantees

- **Checksums signature**: The checksums file was generated in the nox-hq/nox GitHub Actions pipeline and has not been tampered with.
- **Docker image signature**: The container image was built and pushed from the official CI pipeline.
- **SLSA provenance**: The release artifacts were built from a specific commit in the nox-hq/nox repository using the documented build process, meeting SLSA Level 3 requirements.
