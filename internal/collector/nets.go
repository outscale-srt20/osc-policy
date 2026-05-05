package collector

import (
	"context"
	"fmt"

	osc "github.com/outscale/osc-sdk-go/v2"
)

type Nets struct{}

func (Nets) Name() string { return "nets" }

func (Nets) Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error) {
	out := []Resource{}

	// Nets
	netsResp, _, err := client.NetApi.ReadNets(ctx).
		ReadNetsRequest(osc.ReadNetsRequest{}).Execute()
	if err != nil {
		return nil, fmt.Errorf("ReadNets: %w", err)
	}
	for _, n := range netsResp.GetNets() {
		out = append(out, Resource{
			Type:    "outscale_net",
			ID:      n.GetNetId(),
			Address: n.GetNetId(),
			Values:  toSnakeMap(n),
		})
	}

	// Subnets
	subResp, _, err := client.SubnetApi.ReadSubnets(ctx).
		ReadSubnetsRequest(osc.ReadSubnetsRequest{}).Execute()
	if err == nil {
		for _, s := range subResp.GetSubnets() {
			out = append(out, Resource{
				Type:    "outscale_subnet",
				ID:      s.GetSubnetId(),
				Address: s.GetSubnetId(),
				Values:  toSnakeMap(s),
			})
		}
	}

	// Internet Services
	igResp, _, err := client.InternetServiceApi.ReadInternetServices(ctx).
		ReadInternetServicesRequest(osc.ReadInternetServicesRequest{}).Execute()
	if err == nil {
		for _, ig := range igResp.GetInternetServices() {
			out = append(out, Resource{
				Type:    "outscale_internet_service",
				ID:      ig.GetInternetServiceId(),
				Address: ig.GetInternetServiceId(),
				Values:  toSnakeMap(ig),
			})
		}
	}

	return out, nil
}
