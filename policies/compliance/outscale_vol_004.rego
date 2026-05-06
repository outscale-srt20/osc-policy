# METADATA
# id: OSC-VOL-004
# title: Volume sans tag Name
# description: |
#   Un volume BSU sans tag Name est difficile à identifier lors d'un audit
#   ou d'un nettoyage.
# severity: MEDIUM
# category: compliance
# profile: compliance
# resource_types:
#   - outscale_volume
# source: plan,live
# remediation: |
#   Ajouter un tag Name descriptif au volume.
# noncompliant_example: |
#   resource "outscale_volume" "v" { size = 50 }
# compliant_example: |
#   resource "outscale_volume" "v" { size = 50 tags { key = "Name" value = "data-disk-web-01" } }
# references: []
# compliance:
#   anssi_bp_028: ["R1"]
#   secnumcloud_3_2: ["8.1"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.9"]
package compliance.outscale.vol_004

import rego.v1
import data.lib.modules
import data.lib.utils

deny contains msg if {
    some r in all_vols
    not utils.has_tag(object.get(r.values, "tags", []), "Name")
    msg := json.marshal({
        "rule_id": "OSC-VOL-004",
        "rule_title": "Volume sans tag Name",
        "severity": "MEDIUM",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "Volume sans tag Name",
        "remediation": "Ajouter un tag Name au volume.",
    })
}

all_vols := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_volume"]
    live := [r | some r in modules.live_resources; r.type == "outscale_volume"]
    out := array.concat(plan, live)
}
