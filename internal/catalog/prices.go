package catalog

import (
	"fmt"
	"os"

	catalogfs "github.com/outscale-srt20/osc-policy/catalog"
	"gopkg.in/yaml.v3"
)

// Prices représente le catalogue de prix Outscale multi-régions.
type Prices struct {
	DefaultRegion string                    `yaml:"default_region"`
	Thresholds    Thresholds                `yaml:"thresholds"`
	Regions       map[string]RegionalPrices `yaml:"regions"`
}

// RegionalPrices regroupe les tarifs d'une région Outscale.
type RegionalPrices struct {
	Currency         string             `yaml:"currency"`
	VMPerHour        map[string]float64 `yaml:"vm_per_hour"`
	VolumePerGBMonth map[string]float64 `yaml:"volume_per_gb_month"`
	EIPPerMonth      float64            `yaml:"eip_per_month"`
	LBUPerMonth      float64            `yaml:"lbu_per_month"`
	NATPerMonth      float64            `yaml:"nat_per_month"`
	VPNPerMonth      float64            `yaml:"vpn_per_month"`
}

type Thresholds struct {
	VMMonthlyWarn  float64 `yaml:"vm_monthly_warn"`
	VolumeSizeWarn int     `yaml:"volume_size_warn"`
	CPURightsizing float64 `yaml:"cpu_rightsizing"`
	MemRightsizing float64 `yaml:"mem_rightsizing"`
}

// Load charge le catalogue depuis un fichier ou le catalogue embarqué.
func Load(path string) (*Prices, error) {
	var raw []byte
	if path == "" {
		raw = catalogfs.PricesYAML
	} else {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("lecture %s: %w", path, err)
		}
		raw = data
	}
	var p Prices
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parsing catalogue: %w", err)
	}
	if len(p.Regions) == 0 {
		return nil, fmt.Errorf("catalogue invalide: aucune région définie")
	}
	if p.DefaultRegion == "" {
		for name := range p.Regions {
			p.DefaultRegion = name
			break
		}
	}
	return &p, nil
}

// Resolve retourne les tarifs pour une région donnée, avec fallback sur la
// région par défaut si la région demandée n'est pas dans le catalogue.
func (p *Prices) Resolve(region string) (RegionalPrices, string) {
	if region != "" {
		if rp, ok := p.Regions[region]; ok {
			return rp, region
		}
	}
	if rp, ok := p.Regions[p.DefaultRegion]; ok {
		return rp, p.DefaultRegion
	}
	for name, rp := range p.Regions {
		return rp, name
	}
	return RegionalPrices{}, ""
}

// AsData convertit le catalogue en map pour injection dans OPA (data.catalog).
//
// Les tarifs de la région active sont aplatis au niveau racine pour rester
// compatibles avec les règles existantes (data.catalog.eip_per_month, …).
// L'ensemble des régions reste accessible via data.catalog.regions.<nom>.*.
func (p *Prices) AsData(region string) map[string]interface{} {
	rp, effective := p.Resolve(region)

	regionsData := make(map[string]interface{}, len(p.Regions))
	for name, r := range p.Regions {
		regionsData[name] = regionalAsMap(r)
	}

	return map[string]interface{}{
		"region":              effective,
		"default_region":      p.DefaultRegion,
		"currency":            rp.Currency,
		"vm_per_hour":         toInterfaceMap(rp.VMPerHour),
		"volume_per_gb_month": toInterfaceMap(rp.VolumePerGBMonth),
		"eip_per_month":       rp.EIPPerMonth,
		"lbu_per_month":       rp.LBUPerMonth,
		"nat_per_month":       rp.NATPerMonth,
		"vpn_per_month":       rp.VPNPerMonth,
		"thresholds": map[string]interface{}{
			"vm_monthly_warn":  p.Thresholds.VMMonthlyWarn,
			"volume_size_warn": p.Thresholds.VolumeSizeWarn,
			"cpu_rightsizing":  p.Thresholds.CPURightsizing,
			"mem_rightsizing":  p.Thresholds.MemRightsizing,
		},
		"regions": regionsData,
	}
}

func regionalAsMap(r RegionalPrices) map[string]interface{} {
	return map[string]interface{}{
		"currency":            r.Currency,
		"vm_per_hour":         toInterfaceMap(r.VMPerHour),
		"volume_per_gb_month": toInterfaceMap(r.VolumePerGBMonth),
		"eip_per_month":       r.EIPPerMonth,
		"lbu_per_month":       r.LBUPerMonth,
		"nat_per_month":       r.NATPerMonth,
		"vpn_per_month":       r.VPNPerMonth,
	}
}

func toInterfaceMap(m map[string]float64) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
