package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"go.yaml.in/yaml/v4"
	"helm.sh/helm/v3/pkg/chart"
	sigsyaml "sigs.k8s.io/yaml"
)

const (
	yamlIndentSpaces = 2
	httpTimeout      = 30 * time.Second
)

// The files of a chart directory.
const (
	chartFile     = "Chart.yaml"
	valuesFile    = "values.yaml"
	questionsFile = "questions.yaml"
	readmeFile    = "README.md"
	licenseFile   = "LICENSE"
)

type values struct {
	Global struct {
		Cattle struct {
			SystemDefaultRegistry string `yaml:"systemDefaultRegistry"`
		} `yaml:"cattle"`
	} `yaml:"global"`
	Module struct {
		Repository string `yaml:"repository"`
		Tag        string `yaml:"tag"`
	} `yaml:"module"`
}

type upstreamFiles struct {
	readme, license []byte
	// questions is nil if the policy has no questions-ui.yml.
	questions []byte
}

// fetchUpstreamFiles reads the files from the public upstream repository at
// the commit that the signed SBOMs record. Thus the files need no other
// verification.
func fetchUpstreamFiles(rawURL, repository, commit, policyName string) (*upstreamFiles, error) {
	client := &http.Client{Timeout: httpTimeout}
	get := func(path string) ([]byte, error) {
		u, err := url.JoinPath(rawURL, repository, commit, path)
		if err != nil {
			return nil, err
		}
		resp, err := client.Get(u) //nolint:noctx // A timeout on the client is enough for a command-line tool.
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", u, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("download %s: %w", u, errNotFound)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("download %s: unexpected status %s", u, resp.Status)
		}
		return io.ReadAll(resp.Body)
	}
	var f upstreamFiles
	var err error
	if f.readme, err = get("policies/" + policyName + "/README.md"); err != nil {
		return nil, err
	}
	if f.license, err = get("LICENSE"); err != nil {
		return nil, err
	}
	if f.questions, err = get("policies/" + policyName + "/questions-ui.yml"); errors.Is(err, errNotFound) {
		f.questions = nil
	} else if err != nil {
		return nil, err
	}
	return &f, nil
}

// buildChart returns the content of each file of the chart directory. The
// mapping is the same as the one of "kwctl scaffold artifacthub" followed by
// the old pkg2chart, without the ArtifactHub values.
func buildChart(rel *release, version string, files *upstreamFiles) (map[string][]byte, error) {
	a := rel.metadata.Annotations
	title, displayName := a["io.kubewarden.policy.title"], a["io.artifacthub.displayName"]
	if title == "" || displayName == "" {
		return nil, errors.New("the policy metadata needs the annotations io.kubewarden.policy.title and io.artifacthub.displayName")
	}
	rules, err := encodeYAML(&rel.metadata.Rules)
	if err != nil {
		return nil, fmt.Errorf("encode the rules: %w", err)
	}
	annotations := map[string]string{
		"catalog.cattle.io/ui-component": "kubewarden",
		"catalog.cattle.io/hidden":       "true",
		"catalog.cattle.io/type":         "kubewarden-policy",
		"kubewarden/displayName":         displayName,
		"kubewarden/mutation":            strconv.FormatBool(rel.metadata.Mutating),
		"kubewarden/rules":               string(rules),
	}
	if car := &rel.metadata.ContextAwareResources; car.Kind == yaml.SequenceNode && len(car.Content) > 0 {
		var carYAML []byte
		if carYAML, err = encodeYAML(car); err != nil {
			return nil, fmt.Errorf("encode the context aware resources: %w", err)
		}
		annotations["kubewarden/contextAwareResources"] = string(carYAML)
	}
	if r := a["io.artifacthub.resources"]; r != "" {
		annotations["kubewarden/resources"] = r
	}
	if h, ok := a["io.kubewarden.hidden-ui"]; ok {
		var hidden bool
		if hidden, err = strconv.ParseBool(h); err != nil {
			return nil, fmt.Errorf("the io.kubewarden.hidden-ui annotation is %q, but it must be true or false", h)
		}
		annotations["kubewarden/hidden-ui"] = strconv.FormatBool(hidden)
	}
	var keywords []string
	for k := range strings.SplitSeq(a["io.artifacthub.keywords"], ",") {
		if k = strings.TrimSpace(k); k != "" {
			keywords = append(keywords, k)
		}
	}
	chartYAML, err := sigsyaml.Marshal(&chart.Metadata{
		Name:        title,
		Version:     version,
		AppVersion:  version,
		Description: strings.TrimSpace(a["io.kubewarden.policy.description"]),
		Keywords:    keywords,
		Home:        a["io.kubewarden.policy.url"],
		Sources:     []string{rel.image},
		Annotations: annotations,
	})
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", chartFile, err)
	}

	ref, err := name.NewTag(rel.image, name.StrictValidation)
	if err != nil {
		return nil, fmt.Errorf("parse the image %q: %w", rel.image, err)
	}
	var v values
	v.Global.Cattle.SystemDefaultRegistry = ref.RegistryStr()
	v.Module.Repository = ref.RepositoryStr()
	v.Module.Tag = ref.TagStr()
	valuesYAML, err := encodeYAML(v)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", valuesFile, err)
	}

	out := map[string][]byte{
		chartFile:   chartYAML,
		valuesFile:  valuesYAML,
		readmeFile:  files.readme,
		licenseFile: files.license,
	}
	if files.questions != nil {
		out[questionsFile] = files.questions
	}
	return out, nil
}

// writeChart removes a questions.yaml that the new chart does not have, so
// the directory holds only the files of the new chart.
func writeChart(dir string, files map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}
	if _, ok := files[questionsFile]; !ok {
		if err := os.Remove(filepath.Join(dir, questionsFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func encodeYAML(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(yamlIndentSpaces)
	enc.CompactSeqIndent()
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
