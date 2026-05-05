package collector

import (
	"context"
	"fmt"

	osc "github.com/outscale/osc-sdk-go/v2"
)

type Account struct{}

func (Account) Name() string { return "account" }

// Collect interroge les APIs de niveau compte : ApiAccessRules et
// ApiAccessPolicy. Émet trois types de ressources logiques :
//   - outscale_api_access_rule (une par règle)
//   - outscale_api_access_summary (singleton, contient rule_count)
//   - outscale_api_access_policy (singleton)
//
// La ressource summary permet aux policies Rego d'alerter sur l'absence totale
// de règles d'accès (OSC-ACC-003), ce qui serait invisible si on émettait
// uniquement un élément par règle existante.
func (Account) Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error) {
	var out []Resource
	var firstErr error

	rulesResp, _, err := client.ApiAccessRuleApi.ReadApiAccessRules(ctx).
		ReadApiAccessRulesRequest(osc.ReadApiAccessRulesRequest{}).Execute()
	if err != nil {
		firstErr = fmt.Errorf("ReadApiAccessRules: %w", err)
	} else {
		rules := rulesResp.GetApiAccessRules()
		for _, r := range rules {
			values := toSnakeMap(r)
			out = append(out, Resource{
				Type:    "outscale_api_access_rule",
				ID:      r.GetApiAccessRuleId(),
				Address: r.GetApiAccessRuleId(),
				Values:  values,
			})
		}
		out = append(out, Resource{
			Type:    "outscale_api_access_summary",
			ID:      "api-access-summary",
			Address: "api-access-summary",
			Values: map[string]interface{}{
				"rule_count": len(rules),
			},
		})
	}

	polResp, _, err := client.ApiAccessPolicyApi.ReadApiAccessPolicy(ctx).
		ReadApiAccessPolicyRequest(osc.ReadApiAccessPolicyRequest{}).Execute()
	if err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("ReadApiAccessPolicy: %w", err)
		}
	} else {
		policy := polResp.GetApiAccessPolicy()
		out = append(out, Resource{
			Type:    "outscale_api_access_policy",
			ID:      "api-access-policy",
			Address: "api-access-policy",
			Values:  toSnakeMap(policy),
		})
	}

	return out, firstErr
}
