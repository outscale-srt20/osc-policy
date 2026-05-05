package collector

import (
	"context"
	"fmt"
	"os"

	osc "github.com/outscale/osc-sdk-go/v2"
)

// Snapshot est le résultat d'un scan live : une liste de ressources
// (format compatible avec le champ input.resources des policies Rego).
type Snapshot struct {
	Region    string     `json:"region"`
	Resources []Resource `json:"resources"`
	Errors    []string   `json:"errors,omitempty"`
}

// Resource est une ressource collectée depuis l'API Outscale.
type Resource struct {
	Type    string                 `json:"type"`
	ID      string                 `json:"id"`
	Address string                 `json:"address"`
	Values  map[string]interface{} `json:"values"`
}

// Collector interface: chaque collector connaît un type de ressource.
type Collector interface {
	Name() string
	Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error)
}

// Client wrapper.
type Client struct {
	API     *osc.APIClient
	AuthCtx context.Context
	Region  string
}

// NewClient crée un client Outscale.
//
// Précédence des credentials et de la région (du plus fort au plus faible) :
//  1. Arguments explicites (flags CLI)
//  2. Variables d'environnement OUTSCALE_ACCESSKEYID / SECRETKEYID / REGION
//  3. Profil du fichier ~/.osc/config.json (profileName, "default" si vide) ;
//     le fichier peut être relocalisé via OSC_CONFIG_FILE. Si OSC_PROFILE est
//     défini et profileName est vide, la variable d'environnement est utilisée.
//  4. Région par défaut "eu-west-2" (access_key/secret_key restent obligatoires).
func NewClient(region, accessKey, secretKey, profileName string) (*Client, error) {
	if accessKey == "" {
		accessKey = os.Getenv("OUTSCALE_ACCESSKEYID")
	}
	if secretKey == "" {
		secretKey = os.Getenv("OUTSCALE_SECRETKEYID")
	}
	if region == "" {
		region = os.Getenv("OUTSCALE_REGION")
	}
	if profileName == "" {
		profileName = os.Getenv("OSC_PROFILE")
	}

	var host string
	// Ne consulter ~/.osc/config.json que s'il manque au moins une info.
	if accessKey == "" || secretKey == "" || region == "" || profileName != "" {
		prof, err := LoadOSCProfile(profileName)
		if err != nil {
			return nil, err
		}
		if prof != nil {
			if accessKey == "" {
				accessKey = prof.AccessKey
			}
			if secretKey == "" {
				secretKey = prof.SecretKey
			}
			if region == "" {
				region = prof.effectiveRegion()
			}
			host = prof.Host
		}
	}

	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("credentials Outscale introuvables (flags, env OUTSCALE_ACCESSKEYID/SECRETKEYID, ou ~/.osc/config.json)")
	}
	if region == "" {
		region = "eu-west-2"
	}

	cfg := oscConfig(region, host)
	api := oscNewAPIClient(cfg)
	ctx := oscAuthContext(accessKey, secretKey, region)
	return &Client{API: api, AuthCtx: ctx, Region: region}, nil
}

// oscConfig construit une configuration SDK Outscale, en surchargeant
// l'endpoint si un host custom est fourni.
func oscConfig(region, host string) *osc.Configuration {
	cfg := osc.NewConfiguration()
	cfg.Debug = false
	if host != "" && host != "outscale.com" {
		cfg.Servers = osc.ServerConfigurations{
			{URL: fmt.Sprintf("https://api.%s.%s", region, host)},
		}
	}
	return cfg
}

func oscNewAPIClient(cfg *osc.Configuration) *osc.APIClient {
	return osc.NewAPIClient(cfg)
}

func oscAuthContext(accessKey, secretKey, region string) context.Context {
	ctx := context.WithValue(context.Background(), osc.ContextAWSv4, osc.AWSv4{
		AccessKey: accessKey,
		SecretKey: secretKey,
	})
	return context.WithValue(ctx, osc.ContextServerVariables, map[string]string{
		"region": region,
	})
}

// Registry retourne la liste des collectors pour un set donné ("all" = tout).
func Registry(selection []string) []Collector {
	all := map[string]Collector{
		"vms":       &VMs{},
		"volumes":   &Volumes{},
		"sgs":       &SecurityGroups{},
		"ips":       &PublicIPs{},
		"lbus":      &LoadBalancers{},
		"nets":      &Nets{},
		"vpn":       &VPNs{},
		"nics":      &NICs{},
		"snapshots": &Snapshots{},
		"images":    &Images{},
		"keys":      &Keypairs{},
		"access":    &AccessKeys{},
		"oos":       &OOS{},
		"account":   &Account{},
		"eim":       &EIM{},
		"oks":       &OKS{},
	}
	if len(selection) == 0 || (len(selection) == 1 && selection[0] == "all") {
		out := make([]Collector, 0, len(all))
		for _, c := range all {
			out = append(out, c)
		}
		return out
	}
	out := make([]Collector, 0, len(selection))
	for _, name := range selection {
		if c, ok := all[name]; ok {
			out = append(out, c)
		}
	}
	return out
}
