# METADATA
# id: OSC-SG-003
# title: Inbound ouvert à ::/0 (IPv6 all)
# description: |
#   Une règle autorise le trafic entrant IPv6 depuis toute source (::/0),
#   exposant le service à Internet via IPv6 comme si c'était 0.0.0.0/0.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_security_group_rule
# source: plan,live
# remediation: |
#   Restreindre le range IPv6 source à une plage interne (ex: fd00::/8 ou
#   l'ULA de votre organisation).
# noncompliant_example: |
#   resource "outscale_security_group_rule" "v6" {
#     flow     = "Inbound"
#     ip_range = "::/0"
#   }
# compliant_example: |
#   resource "outscale_security_group_rule" "v6" {
#     flow     = "Inbound"
#     ip_range = "fd00:abcd::/32"
#   }
# references: []
# compliance:
#   anssi_bp_028: ["R65", "R67"]
#   secnumcloud_3_2: ["13.2", "13.3"]
#   cis_controls_v8: ["4.4"]
#   iso_27001_2022: ["A.8.20"]
package security.outscale.sg_003

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_sg_rules
    r.values.flow == "Inbound"
    r.values.ip_range == "::/0"
    msg := json.marshal({
        "rule_id":          "OSC-SG-003",
        "rule_title":       "Inbound ouvert à ::/0 (IPv6)",
        "severity":         "HIGH",
        "category":         "security",
        "resource_id":      object.get(r, "id", r.address),
        "resource_type":    r.type,
        "resource_address": r.address,
        "message":          "Security group rule ouvert à ::/0 (IPv6 all)",
        "remediation":      "Restreindre le range IPv6 à une plage privée ou supprimer la règle.",
    })
}

all_sg_rules := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_security_group_rule"]
    live := [r | some r in modules.live_resources; r.type == "outscale_security_group_rule"]
    out := array.concat(plan, live)
}
