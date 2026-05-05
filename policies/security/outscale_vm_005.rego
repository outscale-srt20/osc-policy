# METADATA
# id: OSC-VM-005
# title: VM sans tag Env
# description: |
#   Le tag Env (dev/staging/prod) est nécessaire pour appliquer des politiques
#   différenciées (sauvegardes, rétention, alerting) selon l'environnement.
# severity: MEDIUM
# category: security
# profile: security
# resource_types:
#   - outscale_vm
# source: plan,live
# remediation: |
#   Ajouter un tag `Env` avec la valeur de l'environnement.
# noncompliant_example: |
#   resource "outscale_vm" "vm" {
#     tags { key = "Name" value = "web-01" }
#   }
# compliant_example: |
#   resource "outscale_vm" "vm" {
#     tags { key = "Name" value = "web-01" }
#     tags { key = "Env"  value = "prod" }
#   }
# references: []
# compliance:
#   anssi_bp_028: ["R1"]
#   secnumcloud_3_2: ["8.1"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.9"]
package security.outscale.vm_005

import rego.v1
import data.lib.modules
import data.lib.utils

deny contains msg if {
    some r in all_vms
    not utils.has_tag(object.get(r.values, "tags", []), "Env")
    msg := json.marshal({
        "rule_id": "OSC-VM-005",
        "rule_title": "VM sans tag Env",
        "severity": "MEDIUM",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "VM sans tag Env (dev/staging/prod)",
        "remediation": "Ajouter un tag Env explicite.",
    })
}

all_vms := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_vm"]
    live := [r | some r in modules.live_resources; r.type == "outscale_vm"]
    out := array.concat(plan, live)
}
