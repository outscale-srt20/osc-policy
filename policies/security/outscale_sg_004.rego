# METADATA
# id: OSC-SG-004
# title: All-traffic outbound sans restriction
# description: |
#   Une règle de security group autorise tout le trafic sortant vers n'importe
#   quelle destination. Cela facilite l'exfiltration de données et les
#   communications vers des C2 depuis une VM compromise.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_security_group_rule
# source: plan,live
# remediation: |
#   1. Identifier les destinations externes légitimes (APIs cloud, DNS, NTP...)
#   2. Créer des règles sortantes spécifiques par destination et port
#   3. Bloquer le reste via un deny outbound par défaut
# noncompliant_example: |
#   resource "outscale_security_group_rule" "out" {
#     flow        = "Outbound"
#     ip_range    = "0.0.0.0/0"
#     ip_protocol = "-1"
#   }
# compliant_example: |
#   resource "outscale_security_group_rule" "out_https" {
#     flow            = "Outbound"
#     ip_range        = "0.0.0.0/0"
#     ip_protocol     = "tcp"
#     from_port_range = "443"
#     to_port_range   = "443"
#   }
# references: []
# compliance:
#   anssi_bp_028: ["R65"]
#   secnumcloud_3_2: ["13.3"]
#   cis_controls_v8: ["4.4"]
#   iso_27001_2022: ["A.8.20"]
package security.outscale.sg_004

import rego.v1
import data.lib.modules
import data.lib.utils

deny contains msg if {
    some r in all_sg_rules
    r.values.flow == "Outbound"
    r.values.ip_protocol == "-1"
    utils.is_public_cidr(r.values.ip_range)
    msg := json.marshal({
        "rule_id":          "OSC-SG-004",
        "rule_title":       "All-traffic outbound sans restriction",
        "severity":         "HIGH",
        "category":         "security",
        "resource_id":      object.get(r, "id", r.address),
        "resource_type":    r.type,
        "resource_address": r.address,
        "message":          "Trafic sortant non restreint vers Internet (all-protocols, 0.0.0.0/0)",
        "remediation":      "Créer des règles sortantes ciblées par port/destination.",
    })
}

all_sg_rules := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_security_group_rule"]
    live := [r | some r in modules.live_resources; r.type == "outscale_security_group_rule"]
    out := array.concat(plan, live)
}
