package collector

import (
	"context"
	"fmt"

	osc "github.com/outscale/osc-sdk-go/v2"
)

type Keypairs struct{}

func (Keypairs) Name() string { return "keys" }

func (Keypairs) Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error) {
	resp, _, err := client.KeypairApi.ReadKeypairs(ctx).
		ReadKeypairsRequest(osc.ReadKeypairsRequest{}).Execute()
	if err != nil {
		return nil, fmt.Errorf("ReadKeypairs: %w", err)
	}
	// Pour déterminer l'usage, on lit aussi les VMs
	vmResp, _, _ := client.VmApi.ReadVms(ctx).ReadVmsRequest(osc.ReadVmsRequest{}).Execute()
	used := map[string]bool{}
	for _, v := range vmResp.GetVms() {
		if k := v.GetKeypairName(); k != "" {
			used[k] = true
		}
	}

	out := []Resource{}
	for _, k := range resp.GetKeypairs() {
		values := toSnakeMap(k)
		inUse := used[k.GetKeypairName()]
		out = append(out, Resource{
			Type:    "outscale_keypair",
			ID:      k.GetKeypairName(),
			Address: k.GetKeypairName(),
			Values:  values,
		})
		out[len(out)-1].Values["in_use"] = inUse
	}
	return out, nil
}
