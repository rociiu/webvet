package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/rociiu/webvet/report"
	"github.com/rociiu/webvet/rules"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Severity string   `yaml:"severity"`
	Disable  []string `yaml:"disable"`
	Enable   []string `yaml:"enable"`
}

// Load reads a strict YAML configuration. A missing default configuration is
// not an error; a path explicitly requested by the user is.
func Load(path string, required bool) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !required {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()
	var cfg Config
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.Severity != "" {
		if _, err := report.ParseSeverity(cfg.Severity); err != nil {
			return Config{}, fmt.Errorf("config severity: %w", err)
		}
	}
	known := map[string]bool{}
	for _, meta := range rules.MetadataList() {
		known[meta.ID] = true
	}
	for _, item := range append(append([]string(nil), cfg.Disable...), cfg.Enable...) {
		if !known[item] {
			return Config{}, fmt.Errorf("config references unknown rule %q", item)
		}
	}
	cfg.Disable = normalize(cfg.Disable)
	cfg.Enable = normalize(cfg.Enable)
	return cfg, nil
}

func normalize(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" && !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}
