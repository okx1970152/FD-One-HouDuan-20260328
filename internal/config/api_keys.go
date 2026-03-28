package config

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const generatedAPIKeyPrefix = "xxapi-"

type APIKeyEntry struct {
	APIKey        string    `yaml:"api-key" json:"api-key"`
	CustomerName  string    `yaml:"customer-name,omitempty" json:"customer-name,omitempty"`
	ExpiresAt     time.Time `yaml:"expires-at,omitempty" json:"expires-at,omitempty"`
	CreatedAt     time.Time `yaml:"created-at,omitempty" json:"created-at,omitempty"`
	Enabled       bool      `yaml:"enabled" json:"enabled"`
	Note          string    `yaml:"note,omitempty" json:"note,omitempty"`
	AllowedModels []string  `yaml:"allowed-models,omitempty" json:"allowed-models,omitempty"`
}

type APIKeyEntries []APIKeyEntry

func (entries *APIKeyEntries) UnmarshalYAML(node *yaml.Node) error {
	if node == nil {
		*entries = nil
		return nil
	}

	switch node.Kind {
	case yaml.SequenceNode:
		out := make([]APIKeyEntry, 0, len(node.Content))
		for _, child := range node.Content {
			if child == nil {
				continue
			}
			switch child.Kind {
			case yaml.ScalarNode:
				value := strings.TrimSpace(child.Value)
				if value == "" {
					continue
				}
				out = append(out, APIKeyEntry{APIKey: value, Enabled: true})
			case yaml.MappingNode:
				var entry APIKeyEntry
				if err := child.Decode(&entry); err != nil {
					return err
				}
				out = append(out, entry)
			default:
				return fmt.Errorf("api-keys entries must be scalars or mappings")
			}
		}
		*entries = NormalizeAPIKeyEntries(out)
		return nil
	case yaml.ScalarNode:
		value := strings.TrimSpace(node.Value)
		if value == "" {
			*entries = nil
			return nil
		}
		*entries = APIKeyEntries{{APIKey: value, Enabled: true}}
		return nil
	default:
		return fmt.Errorf("api-keys must be a sequence")
	}
}

func (entries APIKeyEntries) MarshalJSON() ([]byte, error) {
	return json.Marshal([]APIKeyEntry(entries))
}

func NormalizeAPIKeyEntries(entries []APIKeyEntry) APIKeyEntries {
	if len(entries) == 0 {
		return nil
	}
	normalized := make([]APIKeyEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		key := strings.TrimSpace(entry.APIKey)
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		entry.APIKey = key
		entry.CustomerName = strings.TrimSpace(entry.CustomerName)
		entry.Note = strings.TrimSpace(entry.Note)
		entry.AllowedModels = NormalizeAllowedModels(entry.AllowedModels)
		if entry.CreatedAt.IsZero() {
			entry.CreatedAt = time.Now().UTC()
		} else {
			entry.CreatedAt = entry.CreatedAt.UTC()
		}
		if !entry.ExpiresAt.IsZero() {
			entry.ExpiresAt = entry.ExpiresAt.UTC()
		}
		if !entry.Enabled && strings.TrimSpace(entry.APIKey) != "" && entry.CustomerName == "" && entry.Note == "" && entry.ExpiresAt.IsZero() && len(entry.AllowedModels) == 0 {
			entry.Enabled = true
		}
		normalized = append(normalized, entry)
	}
	if len(normalized) == 0 {
		return nil
	}
	return APIKeyEntries(normalized)
}

func NormalizeAllowedModels(models []string) []string {
	if len(models) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(models))
	normalized := make([]string, 0, len(models))
	for _, model := range models {
		trimmed := strings.TrimSpace(model)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	sort.Strings(normalized)
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func (entry APIKeyEntry) IsExpired(now time.Time) bool {
	if entry.ExpiresAt.IsZero() {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	return !entry.ExpiresAt.After(now.UTC())
}

func (cfg *SDKConfig) APIKeyValues() []string {
	if cfg == nil || len(cfg.APIKeys) == 0 {
		return nil
	}
	values := make([]string, 0, len(cfg.APIKeys))
	for _, entry := range cfg.APIKeys {
		if key := strings.TrimSpace(entry.APIKey); key != "" {
			values = append(values, key)
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func GenerateAPIKey() (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	const length = 16

	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	var builder strings.Builder
	builder.Grow(len(generatedAPIKeyPrefix) + length)
	builder.WriteString(generatedAPIKeyPrefix)
	for _, b := range buf {
		builder.WriteByte(alphabet[int(b)%len(alphabet)])
	}
	return builder.String(), nil
}
