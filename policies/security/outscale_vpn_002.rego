# METADATA
# id: OSC-VPN-002
# title: VPN connection sans tag Name
# description: |
#   Sans tag Name, un VPN connection est difficile à identifier dans une
#   liste. Combiné à plusieurs VPN actifs (peering site-to-site multi-DC),
#   l'absence d'identifiant lisible complique la maintenance et l'audit.
# severity: LOW
# category: compliance
# profile: compliance
# resource_types:
#   - outscale_vpn_connection
# source: plan,live
# remediation: |
#   resource "outscale_vpn_connection" "to_onprem" {
#     # ...
#     tags {
#       key   = "Name"
#       value = "vpn-to-onprem-paris"
#     }
#   }
# compliance:
#   iso_27001_2022: ["A.5.9"]
package compliance.outscale.vpn_002

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_vpns
    not has_name_tag(r)
    msg := build(r)
}

has_name_tag(r) if {
    some t in r.values.tags
    t.key == "Name"
}
has_name_tag(r) if {
    r.values.tags.Name
}

build(r) := json.marshal({
    "rule_id": "OSC-VPN-002",
    "rule_title": "VPN connection sans tag Name",
    "severity": "LOW",
    "category": "compliance",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("VPN connection '%s' sans tag Name — identification difficile", [r.address]),
    "remediation": "Ajouter un tag Name décrivant le VPN (ex: vpn-to-onprem-paris).",
})

all_vpns := modules.resources_of_type("outscale_vpn_connection")
