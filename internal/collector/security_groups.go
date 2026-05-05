package collector

import (
	"context"
	"fmt"

	osc "github.com/outscale/osc-sdk-go/v2"
)

type SecurityGroups struct{}

func (SecurityGroups) Name() string { return "sgs" }

func (SecurityGroups) Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error) {
	resp, _, err := client.SecurityGroupApi.ReadSecurityGroups(ctx).
		ReadSecurityGroupsRequest(osc.ReadSecurityGroupsRequest{}).Execute()
	if err != nil {
		return nil, fmt.Errorf("ReadSecurityGroups: %w", err)
	}
	sgs := resp.GetSecurityGroups()
	out := []Resource{}
	for _, sg := range sgs {
		values := toSnakeMap(sg)
		out = append(out, Resource{
			Type:    "outscale_security_group",
			ID:      sg.GetSecurityGroupId(),
			Address: sg.GetSecurityGroupId(),
			Values:  values,
		})

		// Chaque InboundRules → outscale_security_group_rule
		for i, rule := range sg.GetInboundRules() {
			ruleValues := toSnakeMap(rule)
			ruleValues["flow"] = "Inbound"
			ruleValues["security_group_id"] = sg.GetSecurityGroupId()
			flattenFirstRange(ruleValues)
			out = append(out, Resource{
				Type:    "outscale_security_group_rule",
				ID:      fmt.Sprintf("%s-in-%d", sg.GetSecurityGroupId(), i),
				Address: fmt.Sprintf("%s-in-%d", sg.GetSecurityGroupId(), i),
				Values:  ruleValues,
			})
		}
		for i, rule := range sg.GetOutboundRules() {
			ruleValues := toSnakeMap(rule)
			ruleValues["flow"] = "Outbound"
			ruleValues["security_group_id"] = sg.GetSecurityGroupId()
			flattenFirstRange(ruleValues)
			out = append(out, Resource{
				Type:    "outscale_security_group_rule",
				ID:      fmt.Sprintf("%s-out-%d", sg.GetSecurityGroupId(), i),
				Address: fmt.Sprintf("%s-out-%d", sg.GetSecurityGroupId(), i),
				Values:  ruleValues,
			})
		}
	}
	return out, nil
}

// flattenFirstRange aplatit ip_ranges[0] → ip_range et from_port_range/to_port_range.
func flattenFirstRange(v map[string]interface{}) {
	if arr, ok := v["ip_ranges"].([]interface{}); ok && len(arr) > 0 {
		if s, ok := arr[0].(string); ok {
			v["ip_range"] = s
		}
	}
	if from, ok := v["from_port_range"]; ok {
		if f, ok := from.(float64); ok {
			v["from_port_range"] = fmt.Sprintf("%d", int(f))
		}
	}
	if to, ok := v["to_port_range"]; ok {
		if t, ok := to.(float64); ok {
			v["to_port_range"] = fmt.Sprintf("%d", int(t))
		}
	}
}
