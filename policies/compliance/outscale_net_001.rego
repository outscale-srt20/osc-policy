# METADATA
# id: OSC-NET-001
# title: Subnet sans tag Tier
# description: |
#   Un subnet sans tag Tier (public/private/db) empêche la gouvernance
#   des placements et le routage automatisé.
# severity: MEDIUM
# category: compliance
# profile: compliance
# resource_types:
#   - outscale_subnet
# source: plan,live
# remediation: |
#   Ajouter un tag Tier avec une valeur parmi public/private/db.
# noncompliant_example: |
#   resource "outscale_subnet" "s" { net_id = ... ip_range = "10.0.1.0/24" }
# compliant_example: |
#   resource "outscale_subnet" "s" {
#     net_id   = ...
#     ip_range = "10.0.1.0/24"
#     tags { key = "Tier" value = "private" }
#   }
# references: []
# compliance:
#   anssi_bp_028: ["R1"]
#   secnumcloud_3_2: ["8.1"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.9"]
package compliance.outscale.net_001

import rego.v1
import data.lib.modules
import data.lib.utils

deny contains msg if {
    some r in all_subnets
    not utils.has_tag(object.get(r.values, "tags", []), "Tier")
    msg := json.marshal({
        "rule_id": "OSC-NET-001",
        "rule_title": "Subnet sans tag Tier",
        "severity": "MEDIUM",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "Subnet sans tag Tier (public/private/db)",
        "remediation": "Ajouter un tag Tier.",
    })
}

all_subnets := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_subnet"]
    live := [r | some r in modules.live_resources; r.type == "outscale_subnet"]
    out := array.concat(plan, live)
}
