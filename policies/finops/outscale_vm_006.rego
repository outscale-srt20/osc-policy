# METADATA
# id: OSC-VM-006
# title: vm_type non dans la liste approuvée
# description: |
#   La gamme de VMs permise (approved_vm_types) est définie pour respecter la
#   stratégie FinOps et capacity planning. Une VM hors gamme peut tromper les
#   prévisions de coût.
# severity: MEDIUM
# category: finops
# profile: finops
# resource_types:
#   - outscale_vm
# source: plan,live
# remediation: |
#   Choisir un vm_type dans la liste autorisée définie par l'équipe Platform.
# noncompliant_example: |
#   resource "outscale_vm" "vm" {
#     vm_type = "tinav4.c1r1p2"
#   }
# compliant_example: |
#   resource "outscale_vm" "vm" {
#     vm_type = "tinav6.c4r8p1"
#   }
# references: []
# compliance:

#   secnumcloud_3_2: ["8.2"]

#   iso_27001_2022: ["A.5.10"]
package finops.outscale.vm_006

import rego.v1
import data.lib.modules

# Types approuvés — pourra être redéfini par override dans un fichier custom.
approved_types := {
    "tinav5.c1r1p1", "tinav5.c2r4p1", "tinav5.c4r8p1", "tinav5.c4r16p1",
    "tinav5.c8r16p1", "tinav5.c8r32p1", "tinav5.c16r32p1", "tinav5.c16r64p1",
    "tinav6.c1r1p1", "tinav6.c2r4p1", "tinav6.c4r8p1", "tinav6.c4r8p2",
    "tinav6.c4r16p1", "tinav6.c4r16p2", "tinav6.c8r16p1", "tinav6.c8r16p2",
    "tinav6.c8r32p1", "tinav6.c8r32p2", "tinav6.c16r32p1", "tinav6.c16r32p2",
    "tinav6.c16r64p1", "tinav6.c16r64p2",
}

deny contains msg if {
    some r in all_vms
    t := r.values.vm_type
    t != ""
    not t in approved_types
    msg := json.marshal({
        "rule_id": "OSC-VM-006",
        "rule_title": "vm_type non approuvé",
        "severity": "MEDIUM",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": sprintf("vm_type '%v' hors liste approuvée", [t]),
        "remediation": "Utiliser un vm_type de la gamme tinav5 ou tinav6 approuvée.",
    })
}

all_vms := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_vm"]
    live := [r | some r in modules.live_resources; r.type == "outscale_vm"]
    out := array.concat(plan, live)
}
