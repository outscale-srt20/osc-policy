package catalog

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	catalogfs "github.com/outscale-srt20/osc-policy/catalog"
	"gopkg.in/yaml.v3"
)

// Framework représente un référentiel de conformité (ANSSI, ISO, CIS, …).
type Framework struct {
	Code        string    `yaml:"code"`
	Name        string    `yaml:"name"`
	Version     string    `yaml:"version"`
	URL         string    `yaml:"url"`
	Description string    `yaml:"description"`
	Controls    []Control `yaml:"controls"`

	// controlIndex permet une résolution O(1) par ID après chargement.
	controlIndex map[string]*Control
}

// Control représente un contrôle individuel à l'intérieur d'un framework.
type Control struct {
	ID          string `yaml:"id"`
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	URL         string `yaml:"url,omitempty"`
}

// Frameworks agrège tous les référentiels chargés, indexés par code.
type Frameworks struct {
	byCode map[string]*Framework
}

// LoadFrameworks charge les référentiels embarqués, puis optionnellement
// ceux d'un répertoire additionnel (pour usage avancé).
func LoadFrameworks(extraDir string) (*Frameworks, error) {
	fw := &Frameworks{byCode: map[string]*Framework{}}

	// Embarqués
	entries, err := fs.ReadDir(catalogfs.FrameworksFS, "frameworks")
	if err != nil {
		return nil, fmt.Errorf("frameworks embarqués: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := catalogfs.FrameworksFS.ReadFile("frameworks/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("lecture %s: %w", e.Name(), err)
		}
		f, err := parseFramework(data, e.Name())
		if err != nil {
			return nil, err
		}
		fw.byCode[f.Code] = f
	}

	// Additionnels (optionnel)
	if extraDir != "" {
		matches, err := filepath.Glob(filepath.Join(extraDir, "*.yaml"))
		if err != nil {
			return nil, err
		}
		for _, path := range matches {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("lecture %s: %w", path, err)
			}
			f, err := parseFramework(data, path)
			if err != nil {
				return nil, err
			}
			fw.byCode[f.Code] = f
		}
	}

	return fw, nil
}

func parseFramework(data []byte, source string) (*Framework, error) {
	var f Framework
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", source, err)
	}
	if f.Code == "" {
		return nil, fmt.Errorf("%s: champ 'code' manquant", source)
	}
	f.controlIndex = make(map[string]*Control, len(f.Controls))
	for i := range f.Controls {
		c := &f.Controls[i]
		if c.ID == "" {
			return nil, fmt.Errorf("%s: contrôle sans id", source)
		}
		f.controlIndex[c.ID] = c
	}
	return &f, nil
}

// Codes retourne les codes de framework chargés, triés.
func (fw *Frameworks) Codes() []string {
	codes := make([]string, 0, len(fw.byCode))
	for c := range fw.byCode {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	return codes
}

// Get retourne le framework identifié par son code (ou nil si inconnu).
func (fw *Frameworks) Get(code string) *Framework {
	return fw.byCode[code]
}

// All retourne tous les frameworks chargés.
func (fw *Frameworks) All() []*Framework {
	out := make([]*Framework, 0, len(fw.byCode))
	for _, c := range fw.Codes() {
		out = append(out, fw.byCode[c])
	}
	return out
}

// HasControl vérifie qu'un contrôle existe dans un framework donné.
func (fw *Frameworks) HasControl(code, controlID string) bool {
	f, ok := fw.byCode[code]
	if !ok {
		return false
	}
	_, ok = f.controlIndex[controlID]
	return ok
}

// Control retourne un contrôle identifié par (code framework, id contrôle).
func (fw *Frameworks) Control(code, controlID string) *Control {
	f, ok := fw.byCode[code]
	if !ok {
		return nil
	}
	return f.controlIndex[controlID]
}

// ValidateCompliance vérifie que chaque code et chaque contrôle cité dans
// une map compliance existent dans le catalogue chargé. Retourne la liste
// des problèmes (framework inconnu, contrôle inconnu) ; un slice vide
// signifie que tout est valide.
func (fw *Frameworks) ValidateCompliance(compliance map[string][]string) []string {
	var problems []string
	for code, ids := range compliance {
		f, ok := fw.byCode[code]
		if !ok {
			problems = append(problems, fmt.Sprintf("framework inconnu: %q", code))
			continue
		}
		for _, id := range ids {
			if _, ok := f.controlIndex[id]; !ok {
				problems = append(problems, fmt.Sprintf("contrôle %s/%s introuvable", code, id))
			}
		}
	}
	sort.Strings(problems)
	return problems
}
