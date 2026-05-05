# METADATA
# id: OSC-VGW-001
# title: Virtual Gateway orphelin (non rattaché à un Net)
# description: |
#   Un Virtual Gateway créé mais non rattaché à un Net est facturé sans
#   utilité. Cas typique : Net supprimé sans nettoyer le VGW associé,
#   ou VPN connection abandonnée.
# severity: MEDIUM
# category: finops
# profile: finops
# resource_types:
#   - outscale_virtual_gateway
# source: live
# remediation: |
#   1. Vérifier l'absence d'usage : ReadVirtualGateways + ReadVpnConnections
#      filtré sur ce VirtualGatewayId.
#   2. UnlinkVirtualGateway si encore lié.
#   3. DeleteVirtualGateway.
package finops.outscale.vgw_orphan

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_vgws
    is_orphan(r)
    msg := build(r)
}

is_orphan(r) if {
    not r.values.net_to_virtual_gateway_links
}
is_orphan(r) if {
    count(r.values.net_to_virtual_gateway_links) == 0
}

build(r) := json.marshal({
    "rule_id": "OSC-VGW-001",
    "rule_title": "Virtual Gateway orphelin",
    "severity": "MEDIUM",
    "category": "finops",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Virtual Gateway '%s' n'est rattaché à aucun Net — facturé sans utilité", [r.address]),
    "remediation": "UnlinkVirtualGateway (si nécessaire) puis DeleteVirtualGateway.",
})

all_vgws := modules.resources_of_type("outscale_virtual_gateway")
