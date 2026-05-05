# METADATA
# id: OSC-NET-002
# title: Net avec CIDR /8 (trop large)
# description: |
#   Un Net configuré avec un CIDR /8 ou plus large gaspille l'adressage
#   privé et rend l'interconnexion entre Nets plus risquée (chevauchements).
# severity: MEDIUM
# category: security
# profile: security
# resource_types:
#   - outscale_net
# source: plan,live
# remediation: |
#   Utiliser un CIDR /16 (standard) pour les Nets d'usage général.
# noncompliant_example: |
#   resource "outscale_net" "n" { ip_range = "10.0.0.0/8" }
# compliant_example: |
#   resource "outscale_net" "n" { ip_range = "10.42.0.0/16" }
# references: []
# compliance:
#   anssi_bp_028: ["R65", "R66"]
#   secnumcloud_3_2: ["13.1"]
#   cis_controls_v8: ["12.2"]
#   iso_27001_2022: ["A.8.22"]
package security.outscale.net_002

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_nets
    cidr := r.values.ip_range
    regex.match(`^[0-9.]+/([0-9]|1[0-5])$`, cidr)
    msg := json.marshal({
        "rule_id": "OSC-NET-002",
        "rule_title": "Net avec CIDR trop large",
        "severity": "MEDIUM",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": sprintf("Net utilise un CIDR trop large (%v)", [cidr]),
        "remediation": "Réduire à un /16 ou plus spécifique.",
    })
}

all_nets := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_net"]
    live := [r | some r in modules.live_resources; r.type == "outscale_net"]
    out := array.concat(plan, live)
}
