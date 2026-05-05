package collector

import (
	"context"
	"fmt"

	osc "github.com/outscale/osc-sdk-go/v2"
)

type VMs struct{}

func (VMs) Name() string { return "vms" }

func (VMs) Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error) {
	resp, _, err := client.VmApi.ReadVms(ctx).ReadVmsRequest(osc.ReadVmsRequest{}).Execute()
	if err != nil {
		return nil, fmt.Errorf("ReadVms: %w", err)
	}
	vms := resp.GetVms()
	out := make([]Resource, 0, len(vms))
	for _, v := range vms {
		values := toSnakeMap(v)
		// Normaliser security_groups en liste d'IDs pour compatibilité policy
		if sgs, ok := values["security_groups"].([]interface{}); ok {
			ids := []interface{}{}
			for _, sg := range sgs {
				if m, ok := sg.(map[string]interface{}); ok {
					if id, ok := m["security_group_id"]; ok {
						ids = append(ids, id)
					}
				}
			}
			values["security_group_ids"] = ids
		}
		out = append(out, Resource{
			Type:    "outscale_vm",
			ID:      v.GetVmId(),
			Address: v.GetVmId(),
			Values:  values,
		})
	}
	return out, nil
}
