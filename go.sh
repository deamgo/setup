#!/bin/bash

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run via sudo: curl -fsSL https://raw.githubusercontent.com/deamgo/setup/main/go.sh | sudo bash" >&2
  exit 1
fi

REPO_OWNER="deamgo"
REPO_NAME="setup"
REF="${SETUP_REF:-main}"
RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REF}"

WORKDIR="$(mktemp -d)"
KEEP_FILES="${SETUP_KEEP_FILES:-0}"

cleanup() {
  if [ "${KEEP_FILES}" != "1" ]; then
    rm -rf "${WORKDIR}"
  else
    echo "Keeping downloaded files in ${WORKDIR}"
  fi
}
trap cleanup EXIT

MANIFEST="${WORKDIR}/manifest.sha256"
echo "Downloading manifest (${REF})..."
curl -fsSL "${RAW_BASE}/manifest.sha256" -o "${MANIFEST}"

download_and_verify() {
  local checksum="$1"
  local relative_path="$2"
  local target="${WORKDIR}/${relative_path}"
  local target_dir
  target_dir="$(dirname "${target}")"
  mkdir -p "${target_dir}"

  echo "Fetching ${relative_path}..."
  curl -fsSL "${RAW_BASE}/${relative_path}" -o "${target}"

  echo "${checksum}  ${target}" | sha256sum -c -
}

while read -r checksum path; do
  # Skip empty lines or comments
  if [ -z "${checksum}" ] || [[ "${checksum}" =~ ^# ]]; then
    continue
  fi
  download_and_verify "${checksum}" "${path}"
done < "${MANIFEST}"

chmod +x "${WORKDIR}/setup.sh"
chmod +x "${WORKDIR}/https.sh"

echo "Starting setup..."
cd "${WORKDIR}"

# Ensure setup.sh runs in interactive mode by redirecting stdin to /dev/tty if available
# This is necessary because when running via "curl | bash", stdin is the pipe, not the terminal
if [ -c /dev/tty ]; then
  # TTY device is available, use it for interactive input
  "${WORKDIR}/setup.sh" < /dev/tty
else
  # No TTY available, run in non-interactive mode (will use defaults)
  "${WORKDIR}/setup.sh"
fi

echo "Setup completed."

