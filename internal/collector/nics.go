package collector

import (
	"context"
	"fmt"

	osc "github.com/outscale/osc-sdk-go/v2"
)

type NICs struct{}

func (NICs) Name() string { return "nics" }

func (NICs) Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error) {
	resp, _, err := client.NicApi.ReadNics(ctx).
		ReadNicsRequest(osc.ReadNicsRequest{}).Execute()
	if err != nil {
		return nil, fmt.Errorf("ReadNics: %w", err)
	}
	out := []Resource{}
	for _, n := range resp.GetNics() {
		out = append(out, Resource{
			Type:    "outscale_nic",
			ID:      n.GetNicId(),
			Address: n.GetNicId(),
			Values:  toSnakeMap(n),
		})
	}
	return out, nil
}
