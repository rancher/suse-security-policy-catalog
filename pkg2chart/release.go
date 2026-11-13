package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v4"
)

// The files in the release directory. The caller verifies the signatures of
// the module and of the SUSE SBOM before pkg2chart reads them.
const (
	wasmName         = "suse-policy.wasm"
	sbomName         = "policy-sbom.spdx.json"
	upstreamSBOMName = "upstream-policy-sbom.spdx.json"
	metadataName     = "metadata.yml"
	upstreamDocRef   = "DocumentRef-upstream"
)

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxPackage struct {
	SPDXID       string         `json:"SPDXID"`
	VersionInfo  string         `json:"versionInfo"`
	Checksums    []spdxChecksum `json:"checksums"`
	ExternalRefs []struct {
		ReferenceType    string `json:"referenceType"`
		ReferenceLocator string `json:"referenceLocator"`
	} `json:"externalRefs"`
}

type spdxExternalDocumentRef struct {
	ExternalDocumentID string       `json:"externalDocumentId"`
	Checksum           spdxChecksum `json:"checksum"`
}

type spdxDocument struct {
	DocumentDescribes    []string                  `json:"documentDescribes"`
	ExternalDocumentRefs []spdxExternalDocumentRef `json:"externalDocumentRefs"`
	Packages             []spdxPackage             `json:"packages"`
	Relationships        []struct {
		SPDXElementID      string `json:"spdxElementId"`
		RelatedSPDXElement string `json:"relatedSpdxElement"`
		RelationshipType   string `json:"relationshipType"`
	} `json:"relationships"`
}

// policyMetadata is the part of the output of "kwctl inspect -o yaml" that
// the chart needs. The rules stay YAML nodes, so the chart keeps their order.
type policyMetadata struct {
	Rules                 yaml.Node         `yaml:"rules"`
	Mutating              bool              `yaml:"mutating"`
	ContextAwareResources yaml.Node         `yaml:"contextAwareResources"`
	Annotations           map[string]string `yaml:"annotations"`
}

type release struct {
	metadata policyMetadata
	// image is <ociUrl>:<oci tag>, as the signed SUSE SBOM records it.
	image string
	// commit is the upstream commit that the upstream SBOM records.
	commit string
}

// verifyRelease follows the chain from the signed SUSE SBOM: the SUSE SBOM
// records the checksums of the module and of the upstream SBOM, and the
// upstream SBOM records the upstream commit. The release values of the
// request must be equal to the values in the SUSE SBOM.
func verifyRelease(o options) (*release, error) {
	var suse, upstream spdxDocument
	if err := readJSON(filepath.Join(o.releaseDir, sbomName), &suse); err != nil {
		return nil, err
	}
	pkg, err := describedPackage(&suse, sbomName)
	if err != nil {
		return nil, err
	}
	wasmSum, err := fileSHA256(filepath.Join(o.releaseDir, wasmName))
	if err != nil {
		return nil, err
	}
	if !slices.Contains(pkg.Checksums, spdxChecksum{Algorithm: "SHA256", ChecksumValue: wasmSum}) {
		return nil, fmt.Errorf("%s does not record the SHA256 checksum %s of %s", sbomName, wasmSum, wasmName)
	}
	if pkg.VersionInfo != o.releaseVersion {
		return nil, fmt.Errorf("%s records the version %q, but the release version is %q", sbomName, pkg.VersionInfo, o.releaseVersion)
	}
	repository, err := purlRepository(pkg, o.ociTag)
	if err != nil {
		return nil, err
	}
	if rest, ok := strings.CutPrefix(repository, o.ociBase+"/"); !ok || rest == "" || strings.Contains(rest, "/") {
		return nil, fmt.Errorf("%s records the repository %q, which is not a policy under %s", sbomName, repository, o.ociBase)
	}

	upstreamSum, err := fileSHA256(filepath.Join(o.releaseDir, upstreamSBOMName))
	if err != nil {
		return nil, err
	}
	wantRef := spdxExternalDocumentRef{ExternalDocumentID: upstreamDocRef, Checksum: spdxChecksum{Algorithm: "SHA256", ChecksumValue: upstreamSum}}
	if !slices.Contains(suse.ExternalDocumentRefs, wantRef) {
		return nil, fmt.Errorf("%s does not record the SHA256 checksum %s of %s as %s", sbomName, upstreamSum, upstreamSBOMName, upstreamDocRef)
	}
	if err = readJSON(filepath.Join(o.releaseDir, upstreamSBOMName), &upstream); err != nil {
		return nil, err
	}
	root, err := describedPackage(&upstream, upstreamSBOMName)
	if err != nil {
		return nil, err
	}
	if !generatedFrom(&suse, pkg.SPDXID, upstreamDocRef+":"+root.SPDXID) {
		return nil, fmt.Errorf("%s does not record that %s is generated from %s:%s", sbomName, pkg.SPDXID, upstreamDocRef, root.SPDXID)
	}
	if !commitPattern.MatchString(root.VersionInfo) {
		return nil, fmt.Errorf("%s records %q as the version of %s, but it must be a full commit hash", upstreamSBOMName, root.VersionInfo, root.SPDXID)
	}

	var md policyMetadata
	data, err := os.ReadFile(filepath.Join(o.releaseDir, metadataName))
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, &md); err != nil {
		return nil, fmt.Errorf("parse %s: %w", metadataName, err)
	}
	if got := md.Annotations["io.kubewarden.policy.ociUrl"]; got != repository {
		return nil, fmt.Errorf("the io.kubewarden.policy.ociUrl annotation is %q, but %s records the repository %q", got, sbomName, repository)
	}
	want, _, _ := strings.Cut(o.releaseVersion, "+")
	if got := md.Annotations["io.kubewarden.policy.version"]; got != want {
		return nil, fmt.Errorf("the io.kubewarden.policy.version annotation is %q, but the release version %q needs %q", got, o.releaseVersion, want)
	}
	return &release{metadata: md, image: repository + ":" + o.ociTag, commit: root.VersionInfo}, nil
}

// describedPackage uses the same rule as the repackager: the document must
// describe exactly one package, by a DESCRIBES relationship or by
// documentDescribes.
func describedPackage(doc *spdxDocument, file string) (*spdxPackage, error) {
	ids := slices.Clone(doc.DocumentDescribes)
	for _, r := range doc.Relationships {
		if r.RelationshipType == "DESCRIBES" && r.SPDXElementID == "SPDXRef-DOCUMENT" {
			ids = append(ids, r.RelatedSPDXElement)
		}
	}
	slices.Sort(ids)
	if ids = slices.Compact(ids); len(ids) != 1 {
		return nil, fmt.Errorf("%s describes %d packages (%s), but it must describe exactly 1", file, len(ids), strings.Join(ids, " "))
	}
	for i := range doc.Packages {
		if doc.Packages[i].SPDXID == ids[0] {
			return &doc.Packages[i], nil
		}
	}
	return nil, fmt.Errorf("%s describes %q, but it has no package with that SPDXID", file, ids[0])
}

func generatedFrom(doc *spdxDocument, from, to string) bool {
	for _, r := range doc.Relationships {
		if r.RelationshipType == "GENERATED_FROM" && r.SPDXElementID == from && r.RelatedSPDXElement == to {
			return true
		}
	}
	return false
}

// purlRepository reads the OCI purl of the package, for example
// pkg:oci/name@sha256%3A...?repository_url=ghcr.io/org/repo/name&tag=v1.0.6,
// and returns repository_url. The tag in the purl must be ociTag.
func purlRepository(pkg *spdxPackage, ociTag string) (string, error) {
	var purls []string
	for _, r := range pkg.ExternalRefs {
		if r.ReferenceType == "purl" {
			purls = append(purls, r.ReferenceLocator)
		}
	}
	if len(purls) != 1 {
		return "", fmt.Errorf("%s has %d purls for %s, but it must have exactly 1", sbomName, len(purls), pkg.SPDXID)
	}
	rest, ok := strings.CutPrefix(purls[0], "pkg:oci/")
	_, query, hasQuery := strings.Cut(rest, "?")
	if !ok || !hasQuery {
		return "", fmt.Errorf("%s has the purl %q, which is not an OCI purl with qualifiers", sbomName, purls[0])
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return "", fmt.Errorf("%s has the purl %q: %w", sbomName, purls[0], err)
	}
	if got := q.Get("tag"); got != ociTag {
		return "", fmt.Errorf("%s records the OCI tag %q, but the request has %q", sbomName, got, ociTag)
	}
	if q.Get("repository_url") == "" {
		return "", fmt.Errorf("%s has the purl %q without repository_url", sbomName, purls[0])
	}
	return q.Get("repository_url"), nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
