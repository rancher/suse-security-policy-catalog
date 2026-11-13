# pkg2chart

`pkg2chart` writes the chart of one policy of the catalog. The input is a
published release of the policies repository, for example
`rancher/suse-security-policies`. The script `scripts/build-chart.sh` runs it.

The caller downloads these release assets and verifies the signatures of the
first two with cosign:

- `suse-policy.wasm`
- `policy-sbom.spdx.json` (the SUSE SBOM)
- `upstream-policy-sbom.spdx.json`

The caller also writes `metadata.yml`, the output of
`kwctl inspect -o yaml file://suse-policy.wasm`.

`pkg2chart` then does these steps:

1. It checks that `--tag` is `<policy-name>/v<release-version>`.
2. If the chart directory has the same chart version or a newer one, it writes
   a notice and stops. A `+suse.N` version is newer than the same version with
   a lower N or without a suffix.
3. It follows the chain from the SUSE SBOM:
   - The SUSE SBOM records the sha256 of `suse-policy.wasm` and of the upstream
     SBOM.
   - The SUSE SBOM records `--release-version` and, in its purl,
     `--oci-tag` and a repository under `--oci-base`.
   - The upstream SBOM records the upstream commit.
   - The `io.kubewarden.policy.ociUrl` annotation is equal to the repository
     in the purl.
4. It downloads `README.md`, `questions-ui.yml` (if it exists) and `LICENSE`
   from `--upstream-repository` at that commit.
5. It writes `Chart.yaml`, `values.yaml`, `questions.yaml`, `README.md` and
   `LICENSE` to `--output`. It writes nothing if a check fails.

## Usage

```console
go run . \
  --release-dir /path/to/assets \
  --tag ControllerContainerBlockSysctls/v1.0.6 \
  --policy-name ControllerContainerBlockSysctls \
  --release-version 1.0.6 \
  --oci-tag v1.0.6 \
  --oci-base ghcr.io/rancher/suse-security-policies \
  --output ../charts/ControllerContainerBlockSysctls
```

`--upstream-repository` is optional. The default is `kubewarden/policies`.

## Chart values

| Chart field | Source |
|---|---|
| `name` | `io.kubewarden.policy.title` |
| `version`, `appVersion` | `--release-version` |
| `description` | `io.kubewarden.policy.description`, trimmed |
| `keywords` | `io.artifacthub.keywords`, split on commas |
| `home` | `io.kubewarden.policy.url` |
| `sources` | `<ociUrl>:<oci-tag>` |
| `kubewarden/displayName` | `io.artifacthub.displayName` (required) |
| `kubewarden/mutation`, `kubewarden/rules` | `mutating`, `rules` |
| `kubewarden/contextAwareResources` | `contextAwareResources`, if not empty |
| `kubewarden/resources`, `kubewarden/hidden-ui` | `io.artifacthub.resources`, `io.kubewarden.hidden-ui`, if set |
| `catalog.cattle.io/*` | constants for the Rancher UI |
| `values.yaml` | registry, repository and tag of `<ociUrl>:<oci-tag>` |
| `questions.yaml` | `questions-ui.yml` without changes |
