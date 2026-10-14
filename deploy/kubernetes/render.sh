#!/bin/sh
# Renders deploy/kubernetes/hitechcloud-waf.yaml from the Helm chart.
#   deploy/kubernetes/render.sh            # rewrite the file
#   deploy/kubernetes/render.sh --check    # fail when it is out of date (CI)
set -eu
cd "$(dirname "$0")/../.."
out=deploy/kubernetes/hitechcloud-waf.yaml
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
{
  echo "# HiTechCloud WAF - single-node manifests for clusters without Helm."
  echo "# GENERATED from deploy/helm/hitechcloud-waf with deploy/kubernetes/values.yaml"
  echo "# by deploy/kubernetes/render.sh. Do not edit by hand."
  echo "# Install: docs/kubernetes.vi.md (create the Secret, then kubectl apply -k deploy/kubernetes)."
  helm template hitechcloud-waf deploy/helm/hitechcloud-waf \
    --kube-version 1.30.0 --namespace hitechcloud-waf -f deploy/kubernetes/values.yaml
} > "$tmp"
if [ "${1:-}" = "--check" ]; then
  diff -u "$out" "$tmp" || { echo "$out is out of date: run deploy/kubernetes/render.sh" >&2; exit 1; }
else
  cp "$tmp" "$out"
fi
