# METADATA
# id: OSC-SNAP-001
# title: Snapshot public (global_permission == true)
# description: |
#   Un snapshot accessible publiquement permet à tout compte Outscale de
#   restaurer un volume contenant potentiellement des données sensibles.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_snapshot
# source: plan,live
# remediation: |
#   Retirer l'autorisation globale et partager uniquement avec les comptes
#   explicitement autorisés.
# noncompliant_example: |
#   resource "outscale_snapshot_attributes" "s" {
#     permissions_to_create_volume_additions {
#       global_permission = true
#     }
#   }
# compliant_example: |
#   resource "outscale_snapshot_attributes" "s" {
#     permissions_to_create_volume_additions {
#       account_ids = ["123456789012"]
#     }
#   }
# references: []
# compliance:
#   anssi_bp_028: ["R1", "R71"]
#   secnumcloud_3_2: ["9.2", "10.1", "18.1"]
#   cis_controls_v8: ["3.3", "3.11"]
#   iso_27001_2022: ["A.5.15", "A.8.3", "A.8.24"]
#   iso_27017: ["CLD.8.1.5", "CLD.9.5.1"]
package security.outscale.snap_001

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in modules.all_resources
    r.type == "outscale_snapshot_attributes"
    r.values.permissions_to_create_volume_additions.global_permission == true
    msg := build(r)
}
deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_snapshot"
    r.values.account_id == "global"
    msg := build(r)
}

build(r) := json.marshal({
    "rule_id": "OSC-SNAP-001",
    "rule_title": "Snapshot accessible publiquement",
    "severity": "HIGH",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": "Snapshot accessible globalement — risque de fuite de données",
    "remediation": "Retirer global_permission, partager par compte explicite.",
})
