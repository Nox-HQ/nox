#!/usr/bin/env bash
set -euo pipefail

# Nox Security Scanner — GitHub Action entrypoint
# Downloads a pre-built nox binary and runs a security scan.

readonly REPO="nox-hq/nox"

# --- Platform detection ---

detect_platform() {
  local os arch

  case "$(uname -s)" in
    Linux)  os="linux" ;;
    Darwin) os="darwin" ;;
    *)
      echo "::error::Unsupported operating system: $(uname -s)"
      exit 2
      ;;
  esac

  case "$(uname -m)" in
    x86_64|amd64)  arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      echo "::error::Unsupported architecture: $(uname -m)"
      exit 2
      ;;
  esac

  echo "${os}_${arch}"
}

# --- Version resolution ---

# api_get fetches a GitHub API URL and echoes the response body, retrying
# transient failures on the same schedule as fetch_asset below.
#
# It exists because the version lookup used to be a bare `curl -fsSL`, which
# exits non-zero on any 403 and so killed the action before it ever reached the
# retry-hardened download. GitHub answers 403 for rate limiting, and the
# anonymous budget is 60 requests/hour shared across a runner IP — a burst of
# plugin CI runs hits it routinely. The result was a red security gate whose
# only log line was `curl: (22) ... error: 403`, followed by a second red check
# when the SARIF upload found no file. Neither had anything to do with security.
#
# The API base is overridable so tests can point at a stub; it is not a
# supported input.
api_get() {
  local url="$1"
  local attempt=1 max=3 code="" tmp
  tmp="$(mktemp)"

  while :; do
    # The Authorization header pattern uses ${GITHUB_TOKEN:+...}, which the
    # secrets analyzer flags as SEC-161/SEC-163; the env-var name is not a
    # secret. (Inline `# nox:ignore ...` comments break multiline shell
    # commands — leave them out of pipelines.)
    code=$(curl -sSL -w "%{http_code}" -o "${tmp}" \
      -H "Accept: application/vnd.github+json" \
      ${GITHUB_TOKEN:+-H "Authorization: Bearer ${GITHUB_TOKEN}"} \
      "${url}" 2>/dev/null || true)

    if [[ "${code}" == "200" ]]; then
      cat "${tmp}"
      rm -f "${tmp}"
      return 0
    fi

    if (( attempt >= max )); then
      rm -f "${tmp}"
      return 1
    fi

    echo "GitHub API returned HTTP ${code:-unknown}; retrying (${attempt}/${max})..." >&2
    sleep $(( attempt * ${NOX_RETRY_BACKOFF_SECS:-3} ))
    attempt=$(( attempt + 1 ))
  done
}

resolve_version() {
  local version="$1"

  if [[ "${version}" == "latest" ]]; then
    local tag
    tag=$(api_get "${NOX_API_BASE:-https://api.github.com}/repos/${REPO}/releases/latest" \
      | grep -o '"tag_name":[[:space:]]*"[^"]*"' \
      | head -1 \
      | cut -d'"' -f4)

    if [[ -z "${tag}" ]]; then
      echo "::error::Failed to resolve latest nox version from GitHub releases." \
        "If this says HTTP 403 above it is GitHub rate limiting, not a missing" \
        "release — pin an explicit \`version:\` to skip the lookup entirely."
      exit 2
    fi

    # Strip leading 'v' if present.
    version="${tag#v}"
  fi

  echo "${version}"
}

# fetch_asset downloads a release asset to a path, retrying transient failures,
# and echoes the final HTTP status.
#
# The single-shot download this replaces failed a security gate on HTTP 403:
# GitHub throttles release-asset downloads when many jobs fetch at once, and a
# burst of plugin CI runs triggered exactly that. A gate that goes red for a
# reason unrelated to security is one people learn to re-run without reading, so
# a transient throttle must not decide the outcome.
#
# Retries are implemented as a loop rather than curl --retry-all-errors, which
# needs curl >= 7.71; an unknown flag would break the action outright on older
# curl, trading a rare flake for a hard failure. The Authorization header is sent
# when a token is available, matching the version lookup above — curl drops it on
# a cross-host redirect, so it never leaks to the storage backend.
fetch_asset() {
  local url="$1" out="$2"
  local attempt=1 max=3 code=""

  while :; do
    code=$(curl -sSL -w "%{http_code}" -o "${out}" \
      ${GITHUB_TOKEN:+-H "Authorization: Bearer ${GITHUB_TOKEN}"} \
      "${url}" 2>/dev/null || true)

    if [[ -f "${out}" ]] && [[ "${code}" == "200" ]]; then
      echo "${code}"
      return 0
    fi

    if (( attempt >= max )); then
      echo "${code}"
      return 1
    fi

    echo "Download of ${url##*/} returned HTTP ${code:-unknown}; retrying (${attempt}/${max})..." >&2
    rm -f "${out}"
    # Backoff base in seconds. Overridable so tests do not pay the real wait;
    # unset in normal use, which keeps the 3s/6s spacing a throttle needs.
    sleep $(( attempt * ${NOX_RETRY_BACKOFF_SECS:-3} ))
    attempt=$(( attempt + 1 ))
  done
}

# --- Download and install ---

install_nox() {
  local version="$1"
  local platform="$2"
  local archive="nox_${version}_${platform}.tar.gz"
  local url="https://github.com/${REPO}/releases/download/v${version}/${archive}"
  local checksums_url="https://github.com/${REPO}/releases/download/v${version}/checksums.txt"
  local tmp_dir

  tmp_dir="$(mktemp -d)"

  echo "Downloading nox v${version} for ${platform}..."
  local http_code
  http_code=$(fetch_asset "${url}" "${tmp_dir}/${archive}" || true)

  if [[ ! -f "${tmp_dir}/${archive}" ]] || [[ "${http_code}" != "200" ]]; then
    echo "::error::Failed to download nox v${version} for ${platform} (HTTP ${http_code:-unknown})"
    echo "::error::URL: ${url}"
    rm -rf "${tmp_dir}"
    exit 2
  fi

  # Verify checksum if checksums.txt is available.
  if fetch_asset "${checksums_url}" "${tmp_dir}/checksums.txt" >/dev/null 2>&1; then
    local expected actual
    # Match the filename column EXACTLY (sha256sum format: "<hash>  <name>").
    # `grep "$archive"` would also match sibling rows like
    # "<hash>  nox_<v>_linux_amd64.tar.gz.sbom.json" because the substring
    # is contained — concatenating two hashes into `expected` and tripping
    # the comparison below. Strip trailing CR for safety against CRLF
    # checksum files.
    expected=$(awk -v f="${archive}" '$2 == f {print $1}' "${tmp_dir}/checksums.txt" | tr -d '\r')
    if [[ -n "${expected}" ]]; then
      actual=$(sha256sum "${tmp_dir}/${archive}" 2>/dev/null | awk '{print $1}' \
        || shasum -a 256 "${tmp_dir}/${archive}" | awk '{print $1}')
      actual=$(printf '%s' "${actual}" | tr -d '\r')
      if [[ "${expected}" != "${actual}" ]]; then
        echo "::error::Checksum mismatch for ${archive}"
        echo "::error::Expected: ${expected}"
        echo "::error::Actual:   ${actual}"
        rm -rf "${tmp_dir}"
        exit 2
      fi
      echo "Checksum verified."
    fi
  fi

  tar -xzf "${tmp_dir}/${archive}" -C "${tmp_dir}"

  if [[ ! -f "${tmp_dir}/nox" ]]; then
    echo "::error::Archive did not contain 'nox' binary"
    rm -rf "${tmp_dir}"
    exit 2
  fi

  chmod +x "${tmp_dir}/nox"

  local install_dir="${GITHUB_ACTION_PATH:-.}"
  mv "${tmp_dir}/nox" "${install_dir}/nox"
  rm -rf "${tmp_dir}"

  echo "${install_dir}" >> "${GITHUB_PATH}"
  echo "Installed nox v${version} to ${install_dir}"
}

# --- Install required plugins ---

# nox runs only the plugins listed under plugins.required in .nox.yaml.
# Anything not listed is reported as [degraded] with its findings simply
# absent, so a scan whose plugins were never installed looks exactly like a
# scan that found nothing.
#
# `nox install` reads that block and installs what it names — idempotent, and
# a no-op when the project declares no plugins. Without this the action could
# never satisfy a plugins.required entry, which meant any repository scanning
# through this action silently lost its plugin coverage: nox-plugin-freshness
# had to delete its requirement outright, and klarlabs-studio/roady kept
# hand-rolled install steps rather than adopt the action.
install_plugins() {
  local scan_path="$1"
  local install_dir="${GITHUB_ACTION_PATH:-.}"
  local root="${scan_path}"
  [[ -d "${root}" ]] || root="."

  if [[ ! -f "${root}/.nox.yaml" ]]; then
    return 0
  fi

  if ! "${install_dir}/nox" install --root "${root}" --quiet; then
    echo "::error::nox install failed for a plugin named in ${root}/.nox.yaml plugins.required. The scan would run without it and report findings that are absent rather than missing."
    return 1
  fi
}

# --- Run scan ---

run_scan() {
  local scan_path="$1"
  local format="$2"
  local output_dir="$3"
  local fail_on_findings="$4"
  local install_dir="${GITHUB_ACTION_PATH:-.}"

  mkdir -p "${output_dir}"

  # Always include json format so findings.json is available for counting.
  local scan_format="${format}"
  if [[ "${scan_format}" != *"json"* ]] && [[ "${scan_format}" != "all" ]]; then
    scan_format="json,${scan_format}"
  fi

  local exit_code=0
  local extra_args=()
  if [[ -n "${INPUT_SEVERITY_THRESHOLD:-}" ]]; then
    extra_args+=(--severity-threshold "${INPUT_SEVERITY_THRESHOLD}")
  fi
  if [[ -n "${INPUT_MIN_CONFIDENCE:-}" ]]; then
    extra_args+=(--min-confidence "${INPUT_MIN_CONFIDENCE}")
  fi
  if [[ -n "${INPUT_VEX:-}" ]]; then
    extra_args+=(--vex "${INPUT_VEX}")
  fi
  if [[ -n "${INPUT_CHANGED_SINCE:-}" ]]; then
    extra_args+=(--changed-since "${INPUT_CHANGED_SINCE}")
  fi
  if [[ "${INPUT_OFFLINE:-false}" == "true" ]]; then
    extra_args+=(--offline)
  fi
  if [[ "${INPUT_FAIL_ON_DEGRADED:-false}" == "true" ]]; then
    extra_args+=(--fail-on-degraded)
  fi
  "${install_dir}/nox" --format "${scan_format}" --output "${output_dir}" -q scan "${scan_path}" "${extra_args[@]}" || exit_code=$?

  # Set outputs.
  echo "exit-code=${exit_code}" >> "${GITHUB_OUTPUT}"

  # Count findings from findings.json if it exists.
  #
  # grep -c prints the count but EXITS 1 when there are zero matches, so a
  # `|| echo "0"` fallback would fire on top of grep's own "0" and make
  # findings_count the two-line value "0\n0". Writing that to GITHUB_OUTPUT
  # emits a bare second line and fails the whole step with
  # "Unable to process file command 'output' ... Invalid format '0'" — i.e. the
  # action broke on every repository whose scan produced no findings. Swallow
  # grep's exit status instead and default an empty result (unreadable file) to
  # 0, so findings_count is always a single clean integer.
  local findings_count=0
  if [[ -f "${output_dir}/findings.json" ]]; then
    findings_count=$(grep -c '"RuleID"' "${output_dir}/findings.json" 2>/dev/null || true)
    findings_count=${findings_count:-0}
    echo "findings-file=${output_dir}/findings.json" >> "${GITHUB_OUTPUT}"
  fi
  echo "findings-count=${findings_count}" >> "${GITHUB_OUTPUT}"

  if [[ -f "${output_dir}/results.sarif" ]]; then
    echo "sarif-file=${output_dir}/results.sarif" >> "${GITHUB_OUTPUT}"
  fi

  # Job summary.
  {
    echo "### Nox Security Scan"
    echo ""
    if [[ "${exit_code}" -eq 0 ]]; then
      echo ":white_check_mark: **No findings detected**"
    else
      echo ":warning: **${findings_count} finding(s) detected**"
    fi
    echo ""
    echo "| | |"
    echo "|---|---|"
    echo "| **Path** | \`${scan_path}\` |"
    echo "| **Format** | ${format} |"
    echo "| **Output** | \`${output_dir}/\` |"
    echo "| **Findings** | ${findings_count} |"
  } >> "${GITHUB_STEP_SUMMARY}"

  # Handle exit code.
  case "${exit_code}" in
    0)
      echo "Scan completed — no findings."
      ;;
    1)
      echo "Scan completed — ${findings_count} finding(s) detected."
      if [[ "${fail_on_findings}" != "true" ]]; then
        exit_code=0
      fi
      ;;
    2)
      # nox exits 2 both for a hard error and for an incomplete scan under
      # --fail-on-degraded. Reporting the second as "scan failed" sends the
      # reader looking for a crash that did not happen: the scan ran and wrote
      # its reports, but a check could not complete. nox names the specific
      # degradations on stderr; point at them rather than restating the code.
      if [[ "${INPUT_FAIL_ON_DEGRADED:-false}" == "true" ]]; then
        echo "::error::Nox exited 2 — either a scan error, or a check did not complete while fail-on-degraded is set. See the [degraded] lines above and meta.degradations in findings.json."
      else
        echo "::error::Nox scan failed with exit code 2"
      fi
      ;;
    *)
      echo "::error::Nox scan failed with unexpected exit code ${exit_code}"
      ;;
  esac

  return "${exit_code}"
}

# --- Annotate PR ---

annotate_pr() {
  local output_dir="$1"
  local install_dir="${GITHUB_ACTION_PATH:-.}"

  # Only annotate in PR context.
  if [[ -z "${GITHUB_REF:-}" ]] || [[ "${GITHUB_REF}" != refs/pull/* ]]; then
    return 0
  fi

  local findings_file="${output_dir}/findings.json"
  if [[ ! -f "${findings_file}" ]]; then
    return 0
  fi

  echo "Annotating PR with findings..."
  "${install_dir}/nox" annotate --input "${findings_file}" || true
}

# --- Main ---

main() {
  local platform version

  platform="$(detect_platform)"
  version="$(resolve_version "${INPUT_VERSION}")"

  install_nox "${version}" "${platform}"
  install_plugins "${INPUT_PATH}"

  local scan_exit=0
  run_scan "${INPUT_PATH}" "${INPUT_FORMAT}" "${INPUT_OUTPUT}" "${INPUT_FAIL_ON_FINDINGS}" || scan_exit=$?

  if [[ "${INPUT_ANNOTATE:-true}" == "true" ]]; then
    annotate_pr "${INPUT_OUTPUT}"
  fi

  if [[ "${INPUT_PR_COMMENT:-false}" == "true" ]]; then
    local findings_file="${INPUT_OUTPUT}/findings.json"
    if [[ -f "${findings_file}" ]]; then
      bash "${GITHUB_ACTION_PATH:-.}/action-pr-comment.sh" \
        "${findings_file}" \
        "${INPUT_MAX_COMMENTS:-25}" \
        "${INPUT_MIN_SEVERITY:-low}" || true
    fi
  fi

  exit "${scan_exit}"
}

main
