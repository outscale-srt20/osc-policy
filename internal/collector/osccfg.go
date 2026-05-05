package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// OSCProfile représente une entrée du fichier ~/.osc/config.json (format
// partagé avec osc-cli et le provider Terraform Outscale).
type OSCProfile struct {
	AccessKey  string `json:"access_key"`
	SecretKey  string `json:"secret_key"`
	Region     string `json:"region"`
	RegionName string `json:"region_name"` // alias utilisé par osc-cli
	Host       string `json:"host"`
	Protocol   string `json:"protocol"`
	HTTPS      *bool  `json:"https,omitempty"`
	Method     string `json:"method,omitempty"`
}

// effectiveRegion retourne la région à utiliser : "region" en priorité,
// puis "region_name" (alias osc-cli), puis "" si aucun des deux n'est défini.
func (p OSCProfile) effectiveRegion() string {
	if p.Region != "" {
		return p.Region
	}
	return p.RegionName
}

// oscConfigPath retourne le chemin du fichier de config Outscale.
// OSC_CONFIG_FILE surcharge le chemin par défaut ~/.osc/config.json.
func oscConfigPath() string {
	if p := os.Getenv("OSC_CONFIG_FILE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".osc", "config.json")
}

// LoadAllOSCProfiles lit tous les profils de ~/.osc/config.json.
// Retourne (nil, nil) si le fichier n'existe pas (comportement optionnel).
func LoadAllOSCProfiles() (map[string]OSCProfile, error) {
	path := oscConfigPath()
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("lecture %s: %w", path, err)
	}
	var all map[string]OSCProfile
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return all, nil
}

// LoadOSCProfile lit le fichier ~/.osc/config.json et retourne le profil
// demandé. Si profile vaut "", "default" est utilisé. Retourne nil sans
// erreur si le fichier n'existe pas (chemin optionnel).
func LoadOSCProfile(profile string) (*OSCProfile, error) {
	all, err := LoadAllOSCProfiles()
	if err != nil {
		return nil, err
	}
	if all == nil {
		return nil, nil
	}
	if profile == "" {
		profile = "default"
	}
	p, ok := all[profile]
	if !ok {
		available := make([]string, 0, len(all))
		for k := range all {
			available = append(available, k)
		}
		return nil, fmt.Errorf("profil %q introuvable dans %s (disponibles: %v)", profile, oscConfigPath(), available)
	}
	return &p, nil
}

// NewClientFromProfile construit un client Outscale à partir d'un profil déjà
// résolu (lu depuis ~/.osc/config.json, par exemple). Aucune fusion avec les
// env/flags n'est effectuée.
func NewClientFromProfile(prof OSCProfile) (*Client, error) {
	if prof.AccessKey == "" || prof.SecretKey == "" {
		return nil, fmt.Errorf("profil sans access_key/secret_key")
	}
	region := prof.effectiveRegion()
	if region == "" {
		region = "eu-west-2"
	}

	cfg := oscConfig(region, prof.Host)
	api := oscNewAPIClient(cfg)
	ctx := oscAuthContext(prof.AccessKey, prof.SecretKey, region)
	return &Client{API: api, AuthCtx: ctx, Region: region}, nil
}
