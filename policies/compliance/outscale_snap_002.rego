# METADATA
# id: OSC-SNAP-002
# title: Snapshot sans tag Name
# description: |
#   Les snapshots sans tag Name sont difficiles à associer à leur volume
#   source lors d'une restauration.
# severity: MEDIUM
# category: compliance
# profile: compliance
# resource_types:
#   - outscale_snapshot
# source: plan,live
# remediation: |
#   Ajouter un tag Name clair : `{service}-{date}`.
# noncompliant_example: |
#   resource "outscale_snapshot" "s" { volume_id = ... }
# compliant_example: |
#   resource "outscale_snapshot" "s" {
#     volume_id = ...
#     tags { key = "Name" value = "web-db-2026-04" }
#   }
# references: []
# compliance:
#   anssi_bp_028: ["R1"]
#   secnumcloud_3_2: ["8.1", "18.1"]
#   cis_controls_v8: ["1.1", "11.2"]
#   iso_27001_2022: ["A.5.9", "A.8.13"]
package compliance.outscale.snap_002

import rego.v1
import data.lib.modules
import data.lib.utils

deny contains msg if {
    some r in all_snaps
    not utils.has_tag(object.get(r.values, "tags", []), "Name")
    msg := json.marshal({
        "rule_id": "OSC-SNAP-002",
        "rule_title": "Snapshot sans tag Name",
        "severity": "MEDIUM",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "Snapshot sans tag Name",
        "remediation": "Ajouter un tag Name clair.",
    })
}

all_snaps := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_snapshot"]
    live := [r | some r in modules.live_resources; r.type == "outscale_snapshot"]
    out := array.concat(plan, live)
}
