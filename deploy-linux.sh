#!/usr/bin/env bash
set -euo pipefail

FLEET_URL="${FLEET_URL:-}"
ENROLLMENT_TOKEN="${ENROLLMENT_TOKEN:-}"
POLICY_ID="${POLICY_ID:-}"
PROXY="${PROXY:-}"
CA_PATH="${CA_PATH:-./http_ca.crt}"
ARTIFACT_TGZ="${ARTIFACT_TGZ:-./elastic-agent-9.2.2-linux-x86_64.tar.gz}"

usage() {
  echo "Usage: FLEET_URL=... ENROLLMENT_TOKEN=... POLICY_ID=... ./deploy-linux.sh [--proxy URL] [--ca PATH] [--artifact PATH]" >&2
  exit 1
}

if [[ -z "$FLEET_URL" || -z "$ENROLLMENT_TOKEN" || -z "$POLICY_ID" ]]; then
  usage
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy) PROXY="$2"; shift 2 ;;
    --ca) CA_PATH="$2"; shift 2 ;;
    --artifact) ARTIFACT_TGZ="$2"; shift 2 ;;
    *) usage ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 2
fi

command -v curl >/dev/null || { echo "curl required"; exit 3; }
command -v tar >/dev/null || { echo "tar required"; exit 3; }

curl -sk --connect-timeout 5 -I "$FLEET_URL" >/dev/null || { echo "Cannot reach Fleet URL $FLEET_URL"; exit 4; }

WORKDIR="$(mktemp -d /tmp/elastic-agent.XXXX)"
tar -xzf "$ARTIFACT_TGZ" -C "$WORKDIR"
AGENT_DIR="$(find "$WORKDIR" -maxdepth 2 -type f -name elastic-agent | head -n1 | xargs dirname)"

install_agent() {
  local proxy_args=()
  [[ -n "$PROXY" ]] && proxy_args=(--proxy "$PROXY")
  "$AGENT_DIR/elastic-agent" install \
    --url "$FLEET_URL" \
    --enrollment-token "$ENROLLMENT_TOKEN" \
    --policy-id "$POLICY_ID" \
    --certificate-authorities "$CA_PATH" \
    --non-interactive --force "${proxy_args[@]}"
}

validate_agent() {
  systemctl is-active --quiet elastic-agent || systemctl start elastic-agent
  sleep 3
  /opt/Elastic/Agent/elastic-agent status || true
}

install_agent
validate_agent
echo "Elastic Agent deployed and enrolled to policy $POLICY_ID"
