package docgen

import (
	"bufio"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuleMetadata représente les métadonnées extraites d'un fichier .rego.
type RuleMetadata struct {
	ID                  string              `yaml:"id"                   json:"id"`
	Title               string              `yaml:"title"                json:"title"`
	Description         string              `yaml:"description"          json:"description"`
	Severity            string              `yaml:"severity"             json:"severity"`
	Category            string              `yaml:"category"             json:"category"`
	Profile             string              `yaml:"profile"              json:"profile"`
	ResourceTypes       []string            `yaml:"resource_types"       json:"resource_types"`
	Source              string              `yaml:"source"               json:"source"`
	Remediation         string              `yaml:"remediation"          json:"remediation"`
	NoncompliantExample string              `yaml:"noncompliant_example" json:"noncompliant_example"`
	CompliantExample    string              `yaml:"compliant_example"    json:"compliant_example"`
	References          []string            `yaml:"references"           json:"references"`
	Compliance          map[string][]string `yaml:"compliance,omitempty" json:"compliance,omitempty"`

	RegoFile    string `json:"-"`
	RegoContent string `json:"-"`
}

// ParseRegoMetadata parse le bloc `# METADATA` ... `# ...` en haut d'un
// fichier .rego (commentaires préfixés par `# `) comme YAML.
func ParseRegoMetadata(path, content string) (*RuleMetadata, error) {
	// Récupérer les lignes commencant par `# ` au tout début du fichier
	scanner := bufio.NewScanner(strings.NewReader(content))
	var yamlLines []string
	inBlock := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if !inBlock {
			if trimmed == "# METADATA" {
				inBlock = true
				continue
			}
			if trimmed == "" {
				continue
			}
			// première ligne non vide non-commentaire → stop
			if !strings.HasPrefix(trimmed, "#") {
				break
			}
			continue
		}
		// Dans le bloc
		if !strings.HasPrefix(line, "#") {
			break
		}
		stripped := strings.TrimPrefix(line, "#")
		stripped = strings.TrimPrefix(stripped, " ")
		yamlLines = append(yamlLines, stripped)
	}
	if len(yamlLines) == 0 {
		return nil, fmt.Errorf("aucun bloc # METADATA dans %s", path)
	}

	var meta RuleMetadata
	if err := yaml.Unmarshal([]byte(strings.Join(yamlLines, "\n")), &meta); err != nil {
		return nil, fmt.Errorf("yaml metadata %s: %w", path, err)
	}
	meta.RegoFile = path
	meta.RegoContent = content
	return &meta, nil
}
