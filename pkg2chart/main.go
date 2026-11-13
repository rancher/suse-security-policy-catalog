// pkg2chart writes the chart of one policy of the policy catalog. Its
// input is a published release of the policies repository. The caller
// downloads the release assets and verifies their signatures. pkg2chart
// verifies the rest: the SBOM checksums, the release values and the policy
// metadata. Then it reads the policy files from upstream at the commit that
// the signed SBOMs record.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const upstreamRawURL = "https://raw.githubusercontent.com"

// policyNamePattern is the pattern of the repackager. The name forms paths in
// the catalog and in the upstream repository, so it must not hold "/" or "..".
var policyNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type options struct {
	releaseDir         string
	tag                string
	policyName         string
	releaseVersion     string
	ociTag             string
	ociBase            string
	upstreamRepository string
	output             string
}

func main() {
	var o options
	flag.StringVar(&o.releaseDir, "release-dir", "",
		"directory with the release assets, and metadata.yml, the output of 'kwctl inspect -o yaml' for "+wasmName+" (required)")
	flag.StringVar(&o.tag, "tag", "", "tag of the release, for example ControllerContainerBlockSysctls/v1.0.6 (required)")
	flag.StringVar(&o.policyName, "policy-name", "", "upstream directory name of the policy, for example ControllerContainerBlockSysctls (required)")
	flag.StringVar(&o.releaseVersion, "release-version", "", "version of the release, for example 1.0.6 or 1.0.6+suse.1 (required)")
	flag.StringVar(&o.ociTag, "oci-tag", "", "OCI tag of the policy, for example v1.0.6 or v1.0.6_suse.1 (required)")
	flag.StringVar(&o.ociBase, "oci-base", "", "registry and path of the published policies, for example ghcr.io/rancher/suse-security-policies (required)")
	flag.StringVar(&o.upstreamRepository, "upstream-repository", "kubewarden/policies", "owner/repo that holds the policy files")
	flag.StringVar(&o.output, "output", "", "chart directory, for example charts/ControllerContainerBlockSysctls (required)")
	flag.Parse()

	err := o.check(flag.Args())
	if err == nil {
		err = run(o, upstreamRawURL, os.Stdout)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func (o options) check(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unrecognized arguments: %v", args)
	}
	var missing []string
	for _, f := range [][2]string{
		{"release-dir", o.releaseDir}, {"tag", o.tag}, {"policy-name", o.policyName}, {"release-version", o.releaseVersion},
		{"oci-tag", o.ociTag}, {"oci-base", o.ociBase}, {"upstream-repository", o.upstreamRepository}, {"output", o.output},
	} {
		if strings.TrimSpace(f[1]) == "" {
			missing = append(missing, "--"+f[0])
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("these flags are required and must not be empty: %s", strings.Join(missing, ", "))
	}
	if !policyNamePattern.MatchString(o.policyName) || strings.Contains(o.policyName, "..") {
		return fmt.Errorf("the policy name %q is not valid", o.policyName)
	}
	return nil
}

// run writes nothing before every check passed, so a failed run leaves the
// chart directory as it was.
func run(o options, rawURL string, out io.Writer) error {
	if want := o.policyName + "/v" + o.releaseVersion; o.tag != want {
		return fmt.Errorf("the tag is %q, but the policy name and the release version give %q", o.tag, want)
	}
	current, err := currentChartVersion(o.output)
	if err != nil {
		return err
	}
	if current != "" {
		var c int
		if c, err = compareVersions(current, o.releaseVersion); err != nil {
			return err
		}
		if c >= 0 {
			_, err = fmt.Fprintf(out, "::notice::%s already has the chart version %s, which is the same as %s or newer. Nothing to do\n",
				o.output, current, o.releaseVersion)
			return err
		}
	}
	rel, err := verifyRelease(o)
	if err != nil {
		return fmt.Errorf("the release %s is not valid: %w", o.tag, err)
	}
	files, err := fetchUpstreamFiles(rawURL, o.upstreamRepository, rel.commit, o.policyName)
	if err != nil {
		return err
	}
	chart, err := buildChart(rel, o.releaseVersion, files)
	if err != nil {
		return err
	}
	if err = writeChart(o.output, chart); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Wrote %s for %s, from the upstream commit %s\n", o.output, o.tag, rel.commit)
	return err
}

// errNotFound marks an upstream file that does not exist at the commit.
var errNotFound = errors.New("not found")
