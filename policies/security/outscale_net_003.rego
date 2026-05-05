# METADATA
# id: OSC-NET-003
# title: Internet Service sans tag Name
# description: |
#   Les Internet Services (gateways) sans tag Name sont difficiles à
#   identifier dans les consoles et dans les factures.
# severity: LOW
# category: security
# profile: security
# resource_types:
#   - outscale_internet_service
# source: plan,live
# remediation: |
#   Ajouter un tag Name identifiant le Net associé.
# noncompliant_example: |
#   resource "outscale_internet_service" "ig" {}
# compliant_example: |
#   resource "outscale_internet_service" "ig" {
#     tags { key = "Name" value = "igw-prod" }
#   }
# references: []
# compliance:
#   anssi_bp_028: ["R1"]
#   secnumcloud_3_2: ["8.1"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.9"]
package security.outscale.net_003

import rego.v1
import data.lib.modules
import data.lib.utils

deny contains msg if {
    some r in all_igws
    not utils.has_tag(object.get(r.values, "tags", []), "Name")
    msg := json.marshal({
        "rule_id": "OSC-NET-003",
        "rule_title": "Internet Service sans tag Name",
        "severity": "LOW",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "Internet Service sans tag Name",
        "remediation": "Ajouter un tag Name.",
    })
}

all_igws := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_internet_service"]
    live := [r | some r in modules.live_resources; r.type == "outscale_internet_service"]
    out := array.concat(plan, live)
}
