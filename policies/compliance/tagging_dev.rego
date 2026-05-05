# METADATA
# id: OSC-TAG-002
# title: VM dev sans tag ExpiresAt
# description: |
#   Toute VM dans l'environnement dev doit porter un tag ExpiresAt pour
#   permettre le nettoyage automatique après expiration.
# severity: LOW
# category: compliance
# profile: compliance
# resource_types:
#   - outscale_vm
# source: plan,live
# remediation: |
#   Ajouter un tag `ExpiresAt` au format ISO 8601 aux VMs de dev.
# noncompliant_example: |
#   resource "outscale_vm" "v" {
#     tags { key = "Env" value = "dev" }
#   }
# compliant_example: |
#   resource "outscale_vm" "v" {
#     tags { key = "Env"       value = "dev" }
#     tags { key = "ExpiresAt" value = "2026-12-31T23:59:59Z" }
#   }
# references: []
# compliance:
#   secnumcloud_3_2: ["8.2"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.9", "A.5.10"]
package compliance.outscale.tag_002

import rego.v1
import data.lib.modules
import data.lib.utils

deny contains msg if {
    some r in all_vms
    tags := object.get(r.values, "tags", [])
    utils.get_tag(tags, "Env") == "dev"
    not utils.has_tag(tags, "ExpiresAt")
    msg := json.marshal({
        "rule_id": "OSC-TAG-002",
        "rule_title": "VM dev sans ExpiresAt",
        "severity": "LOW",
        "category": "compliance",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "VM dev sans tag ExpiresAt",
        "remediation": "Ajouter un tag ExpiresAt ISO 8601.",
    })
}

all_vms := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_vm"]
    live := [r | some r in modules.live_resources; r.type == "outscale_vm"]
    out := array.concat(plan, live)
}
