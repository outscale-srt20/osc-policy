# METADATA
# id: OSC-CGW-001
# title: Client Gateway sans VPN connection associée
# description: |
#   Un Client Gateway sans VPN connection active n'est pas utilisé. Soit
#   le VPN a été supprimé sans nettoyer le CGW, soit le CGW a été créé en
#   préparation d'une migration jamais finalisée.
# severity: LOW
# category: finops
# profile: finops
# resource_types:
#   - outscale_client_gateway
# source: live
# remediation: |
#   1. Confirmer l'absence d'usage : ReadVpnConnections filtré sur ce
#      ClientGatewayId.
#   2. DeleteClientGateway si abandonné.
package finops.outscale.cgw_orphan

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_cgws
    not used_by_vpn(r.values.client_gateway_id)
    msg := build(r)
}

# Cross-resource: check if any VPN connection uses this CGW.
used_by_vpn(cgw_id) if {
    some v in modules.resources_of_type("outscale_vpn_connection")
    v.values.client_gateway_id == cgw_id
}

build(r) := json.marshal({
    "rule_id": "OSC-CGW-001",
    "rule_title": "Client Gateway sans VPN connection associée",
    "severity": "LOW",
    "category": "finops",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Client Gateway '%s' n'est utilisé par aucun VPN — orphelin", [r.address]),
    "remediation": "Confirmer l'absence d'usage actif, puis DeleteClientGateway.",
})

all_cgws := modules.resources_of_type("outscale_client_gateway")
