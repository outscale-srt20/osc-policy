package collector

import (
	"context"
	"fmt"

	osc "github.com/outscale/osc-sdk-go/v2"
)

type PublicIPs struct{}

func (PublicIPs) Name() string { return "ips" }

func (PublicIPs) Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error) {
	resp, _, err := client.PublicIpApi.ReadPublicIps(ctx).
		ReadPublicIpsRequest(osc.ReadPublicIpsRequest{}).Execute()
	if err != nil {
		return nil, fmt.Errorf("ReadPublicIps: %w", err)
	}
	ips := resp.GetPublicIps()
	out := make([]Resource, 0, len(ips))
	for _, ip := range ips {
		values := toSnakeMap(ip)
		out = append(out, Resource{
			Type:    "outscale_public_ip",
			ID:      ip.GetPublicIpId(),
			Address: ip.GetPublicIpId(),
			Values:  values,
		})
	}
	return out, nil
}
