# Kubewarden policy-catalog

This repository contains the catalog of Kubewarden policies to be consumed by the Rancher UI. The catalog is published to GitHub Pages at [https://kubewarden.github.io/policy-catalog/](https://kubewarden.github.io/policy-catalog/).

## Release Policy Workflow

The workflow `.github/workflows/release_policy.yml` builds the chart of a
policy from a published release of the policies repository, and opens a pull
request with it. After the merge, `release.yml` releases the chart.

### Triggering the Workflow

The workflow starts in two ways:

1. **Repository dispatch.** The `release-catalog` job of the policies
   repository sends this event for each published release:

   ```jsonc
   {
     "event_type": "release-policy",
     "client_payload": {
       "owner": "rancher",
       "repo": "suse-security-policies",
       "tag": "ControllerContainerBlockSysctls/v1.0.6",
       "policy_name": "ControllerContainerBlockSysctls",
       "release_version": "1.0.6",
       "oci_tag": "v1.0.6"
     }
   }
   ```

   A revision has the tag `<name>/v<version>+suse.<N>`, the release version
   `<version>+suse.<N>` and the OCI tag `v<version>_suse.<N>`.

2. **Workflow dispatch.** A person gives the inputs `tag`, `policy-name`,
   `release-version` and `oci-tag`, with the same values.

The workflow does not trust these values. It compares them with the signed
release, and it fails if they differ.

### What the Workflow Does

1. If the branch `release-policy/<tag>` exists, the workflow does nothing.
2. It runs `scripts/build-chart.sh`. The script:
   - fails if `owner`/`repo` differ from `POLICIES_REPOSITORY`,
   - downloads the release assets,
   - verifies the signatures of `suse-policy.wasm` and of the SUSE SBOM
     against the identity
     `https://github.com/<POLICIES_REPOSITORY>/.github/workflows/sync-upstream-releases.yaml@refs/heads/main`,
   - runs `pkg2chart`, which verifies the rest and writes
     `charts/<policy_name>/`. See [pkg2chart/README.md](pkg2chart/README.md).
3. If the chart changed, it opens a pull request.

If the chart already has the same version or a newer one, nothing changes.
Thus the policies repository can send the same event again.

### Configuration

| Name | Kind | Default |
|---|---|---|
| `POLICIES_REPOSITORY` | repository variable | `rancher/suse-security-policies` |
| `POLICIES_OCI_BASE` | repository variable | `ghcr.io/rancher/suse-security-policies` |
| `APP_ID`, `APP_PRIVATE_KEY` | secrets | none |

The GitHub App must be installed on the owner of `POLICIES_REPOSITORY`, with
the `contents: read` permission on it. The policies repository is private, so
the release assets need this token.

A fork sets the two variables to its own policies repository and registry.

### Run it locally

Install gh, cosign, kwctl and Go. Log in with `gh auth login` as a user that
can read the policies repository. Then run:

```console
TAG=ControllerContainerBlockSysctls/v1.0.6 \
POLICY_NAME=ControllerContainerBlockSysctls \
RELEASE_VERSION=1.0.6 \
OCI_TAG=v1.0.6 \
POLICIES_REPOSITORY=rancher/suse-security-policies \
POLICIES_OCI_BASE=ghcr.io/rancher/suse-security-policies \
scripts/build-chart.sh
```

The script writes `charts/ControllerContainerBlockSysctls/`. It opens no pull
request.
