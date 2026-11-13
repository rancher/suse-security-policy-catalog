package main

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	sigsyaml "sigs.k8s.io/yaml"
)

var revisionPattern = regexp.MustCompile(`^[1-9][0-9]*$`)

// currentChartVersion returns "" if the directory has no chart yet.
func currentChartVersion(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, chartFile))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	var c struct {
		Version string `json:"version"`
	}
	if err := sigsyaml.Unmarshal(data, &c); err != nil {
		return "", fmt.Errorf("parse %s: %w", filepath.Join(dir, chartFile), err)
	}
	if c.Version == "" {
		return "", fmt.Errorf("%s has no version", filepath.Join(dir, chartFile))
	}
	return c.Version, nil
}

// compareVersions orders by SemVer precedence first. SemVer ignores build
// metadata, so for equal precedence the SUSE revision decides: "+suse.N" is
// revision N, and no build metadata is revision 0.
func compareVersions(a, b string) (int, error) {
	va, err := semver.StrictNewVersion(a)
	if err != nil {
		return 0, fmt.Errorf("the version %q is not valid SemVer: %w", a, err)
	}
	vb, err := semver.StrictNewVersion(b)
	if err != nil {
		return 0, fmt.Errorf("the version %q is not valid SemVer: %w", b, err)
	}
	if c := va.Compare(vb); c != 0 {
		return c, nil
	}
	ra, err := suseRevision(va)
	if err != nil {
		return 0, err
	}
	rb, err := suseRevision(vb)
	if err != nil {
		return 0, err
	}
	return cmp.Compare(ra, rb), nil
}

func suseRevision(v *semver.Version) (int, error) {
	if v.Metadata() == "" {
		return 0, nil
	}
	n, ok := strings.CutPrefix(v.Metadata(), "suse.")
	if !ok || !revisionPattern.MatchString(n) {
		return 0, fmt.Errorf("the version %q has the build metadata %q, but only suse.N is allowed", v.Original(), v.Metadata())
	}
	return strconv.Atoi(n)
}
