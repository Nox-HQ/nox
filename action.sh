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

resolve_version() {
  local version="$1"

  if [[ "${version}" == "latest" ]]; then
    local tag
    tag=$(curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      ${GITHUB_TOKEN:+-H "Authorization: Bearer ${GITHUB_TOKEN}"} \
      "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep -o '"tag_name":\s*"[^"]*"' \
      | head -1 \
      | cut -d'"' -f4)

    if [[ -z "${tag}" ]]; then
      echo "::error::Failed to resolve latest nox version from GitHub releases"
      exit 2
    fi

    # Strip leading 'v' if present.
    version="${tag#v}"
  fi

  echo "${version}"
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
  http_code=$(curl -fsSL -w "%{http_code}" -o "${tmp_dir}/${archive}" "${url}" 2>/dev/null || true)

  if [[ ! -f "${tmp_dir}/${archive}" ]] || [[ "${http_code}" != "200" ]]; then
    echo "::error::Failed to download nox v${version} for ${platform} (HTTP ${http_code:-unknown})"
    echo "::error::URL: ${url}"
    rm -rf "${tmp_dir}"
    exit 2
  fi

  # Verify checksum if checksums.txt is available.
  if curl -fsSL -o "${tmp_dir}/checksums.txt" "${checksums_url}" 2>/dev/null; then
    local expected actual
    expected=$(grep "${archive}" "${tmp_dir}/checksums.txt" | awk '{print $1}')
    if [[ -n "${expected}" ]]; then
      actual=$(sha256sum "${tmp_dir}/${archive}" 2>/dev/null | awk '{print $1}' \
        || shasum -a 256 "${tmp_dir}/${archive}" | awk '{print $1}')
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
  "${install_dir}/nox" --format "${scan_format}" --output "${output_dir}" -q scan "${scan_path}" || exit_code=$?

  # Set outputs.
  echo "exit-code=${exit_code}" >> "${GITHUB_OUTPUT}"

  # Count findings from findings.json if it exists.
  local findings_count=0
  if [[ -f "${output_dir}/findings.json" ]]; then
    findings_count=$(grep -c '"RuleID"' "${output_dir}/findings.json" 2>/dev/null || echo "0")
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
      echo "::error::Nox scan failed with exit code 2"
      ;;
    *)
      echo "::error::Nox scan failed with unexpected exit code ${exit_code}"
      ;;
  esac

  return "${exit_code}"
}

# --- Main ---

main() {
  local platform version

  platform="$(detect_platform)"
  version="$(resolve_version "${INPUT_VERSION}")"

  install_nox "${version}" "${platform}"
  run_scan "${INPUT_PATH}" "${INPUT_FORMAT}" "${INPUT_OUTPUT}" "${INPUT_FAIL_ON_FINDINGS}"
}

main
