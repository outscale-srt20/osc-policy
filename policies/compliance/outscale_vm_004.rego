# METADATA
# id: OSC-VM-004
# title: VM sans tag Name
# description: |
#   Une VM sans tag Name est difficile à identifier dans la console Outscale,
#   dans les factures et lors des audits. C'est aussi un blocage pour la
#   gouvernance FinOps.
# severity: MEDIUM
# category: compliance
# profile: compliance
# resource_types:
#   - outscale_vm
# source: plan,live
# remediation: |
#   Ajouter un tag `Name` explicite, par ex. `{service}-{env}-{index}`.
# noncompliant_example: |
#   resource "outscale_vm" "vm" {
#     image_id = "ami-12345678"
#   }
# compliant_example: |
#   resource "outscale_vm" "vm" {
#     image_id = "ami-12345678"
#     tags {
#       key   = "Name"
#       value = "web-prod-01"
#     }
#   }
# references: []
# compliance:
#   anssi_bp_028: ["R1"]
#   secnumcloud_3_2: ["8.1"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.9"]
package compliance.outscale.vm_004

import rego.v1
import data.lib.modules
import data.lib.utils

deny contains msg if {
    some r in all_vms
    not utils.has_tag(object.get(r.values, "tags", []), "Name")
    msg := json.marshal({
        "rule_id": "OSC-VM-004",
        "rule_title": "VM sans tag Name",
        "severity": "MEDIUM",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "VM sans tag Name",
        "remediation": "Ajouter un tag Name descriptif.",
    })
}

all_vms := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_vm"]
    live := [r | some r in modules.live_resources; r.type == "outscale_vm"]
    out := array.concat(plan, live)
}
