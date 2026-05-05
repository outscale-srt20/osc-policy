package collector

import (
	"context"
	"fmt"

	osc "github.com/outscale/osc-sdk-go/v2"
)

type VPNs struct{}

func (VPNs) Name() string { return "vpn" }

func (VPNs) Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error) {
	out := []Resource{}

	resp, _, err := client.VpnConnectionApi.ReadVpnConnections(ctx).
		ReadVpnConnectionsRequest(osc.ReadVpnConnectionsRequest{}).Execute()
	if err != nil {
		return nil, fmt.Errorf("ReadVpnConnections: %w", err)
	}
	for _, v := range resp.GetVpnConnections() {
		out = append(out, Resource{
			Type:    "outscale_vpn_connection",
			ID:      v.GetVpnConnectionId(),
			Address: v.GetVpnConnectionId(),
			Values:  toSnakeMap(v),
		})
	}

	cgResp, _, err := client.ClientGatewayApi.ReadClientGateways(ctx).
		ReadClientGatewaysRequest(osc.ReadClientGatewaysRequest{}).Execute()
	if err == nil {
		for _, cg := range cgResp.GetClientGateways() {
			out = append(out, Resource{
				Type:    "outscale_client_gateway",
				ID:      cg.GetClientGatewayId(),
				Address: cg.GetClientGatewayId(),
				Values:  toSnakeMap(cg),
			})
		}
	}

	vgResp, _, err := client.VirtualGatewayApi.ReadVirtualGateways(ctx).
		ReadVirtualGatewaysRequest(osc.ReadVirtualGatewaysRequest{}).Execute()
	if err == nil {
		for _, vg := range vgResp.GetVirtualGateways() {
			out = append(out, Resource{
				Type:    "outscale_virtual_gateway",
				ID:      vg.GetVirtualGatewayId(),
				Address: vg.GetVirtualGatewayId(),
				Values:  toSnakeMap(vg),
			})
		}
	}

	return out, nil
}
