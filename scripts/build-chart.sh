#!/usr/bin/env bash
# Builds charts/<POLICY_NAME> from a published release of the policies
# repository. The workflow release_policy.yml runs this script. A person can
# run it with a gh login that can read the policies repository.
#
# Needs gh, cosign, kwctl and go, and these variables: TAG, POLICY_NAME,
# RELEASE_VERSION, OCI_TAG, POLICIES_REPOSITORY and POLICIES_OCI_BASE.
# SOURCE_REPOSITORY is optional. It is the owner/repo of the request, and it
# must be equal to POLICIES_REPOSITORY.
set -euo pipefail

for v in TAG POLICY_NAME RELEASE_VERSION OCI_TAG POLICIES_REPOSITORY POLICIES_OCI_BASE; do
  if [ -z "${!v:-}" ]; then
    echo "::error::$v must be set" >&2
    exit 1
  fi
done
if [ -n "${SOURCE_REPOSITORY:-}" ] && [ "$SOURCE_REPOSITORY" != "$POLICIES_REPOSITORY" ]; then
  echo "::error::the request comes from $SOURCE_REPOSITORY, but this catalog builds charts from $POLICIES_REPOSITORY" >&2
  exit 1
fi

# The repackager signs with this identity. The catalog derives it from its own
# configuration, never from the request.
identity="https://github.com/${POLICIES_REPOSITORY}/.github/workflows/sync-upstream-releases.yaml@refs/heads/main"
issuer="https://token.actions.githubusercontent.com"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A draft can still change, and it has no final assets.
draft="$(gh release view "$TAG" --repo "$POLICIES_REPOSITORY" --json isDraft --jq .isDraft)"
if [ "$draft" != "false" ]; then
  echo "::error::$TAG in $POLICIES_REPOSITORY is not a published release" >&2
  exit 1
fi

gh release download "$TAG" --repo "$POLICIES_REPOSITORY" --dir "$work" \
  --pattern suse-policy.wasm \
  --pattern suse-policy.wasm.bundle.sigstore \
  --pattern policy-sbom.spdx.json \
  --pattern policy-sbom.spdx.jsonl.bundle.sigstore \
  --pattern upstream-policy-sbom.spdx.json

# pkg2chart verifies the rest of the chain, starting from these two files.
for pair in suse-policy.wasm:suse-policy.wasm.bundle.sigstore policy-sbom.spdx.json:policy-sbom.spdx.jsonl.bundle.sigstore; do
  cosign verify-blob \
    --bundle "$work/${pair#*:}" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer "$issuer" \
    "$work/${pair%%:*}"
done

kwctl inspect -o yaml "file://$work/suse-policy.wasm" > "$work/metadata.yml"

cd "$root/pkg2chart"
go run . \
  --release-dir "$work" \
  --tag "$TAG" \
  --policy-name "$POLICY_NAME" \
  --release-version "$RELEASE_VERSION" \
  --oci-tag "$OCI_TAG" \
  --oci-base "$POLICIES_OCI_BASE" \
  --output "$root/charts/$POLICY_NAME"
