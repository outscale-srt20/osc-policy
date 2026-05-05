# METADATA
# id: OSC-VM-002
# title: VM hors subnet (pas dans un Net)
# description: |
#   Une VM lancée sans subnet_id est placée dans le réseau "public" Outscale,
#   avec une IP publique automatique et aucune isolation réseau. Toute charge
#   de travail doit être placée dans un subnet d'un Net (VPC équivalent).
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_vm
# source: plan,live
# remediation: |
#   1. Créer un Net (VPC) et un Subnet privé
#   2. Référencer le subnet_id dans la VM
#   3. Utiliser un NAT Gateway ou une EIP/LBU pour la connectivité sortante
# noncompliant_example: |
#   resource "outscale_vm" "vm" {
#     image_id = "ami-12345678"
#     vm_type  = "tinav5.c2r4p1"
#   }
# compliant_example: |
#   resource "outscale_vm" "vm" {
#     image_id  = "ami-12345678"
#     vm_type   = "tinav5.c2r4p1"
#     subnet_id = outscale_subnet.private.subnet_id
#   }
# references: []
# compliance:
#   anssi_bp_028: ["R66"]
#   secnumcloud_3_2: ["9.2", "13.1"]
#   cis_controls_v8: ["12.2"]
#   iso_27001_2022: ["A.8.20", "A.8.22"]
#   iso_27017: ["CLD.9.5.1"]
package security.outscale.vm_002

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_vms
    not r.values.subnet_id
    msg := build(r)
}
deny contains msg if {
    some r in all_vms
    r.values.subnet_id == ""
    msg := build(r)
}

build(r) := json.marshal({
    "rule_id":          "OSC-VM-002",
    "rule_title":       "VM hors subnet",
    "severity":         "HIGH",
    "category":         "security",
    "resource_id":      object.get(r, "id", r.address),
    "resource_type":    r.type,
    "resource_address": r.address,
    "message":          "VM lancée sans subnet_id (pas dans un Net)",
    "remediation":      "Placer la VM dans un subnet d'un Net Outscale.",
})

all_vms := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_vm"]
    live := [r | some r in modules.live_resources; r.type == "outscale_vm"]
    out := array.concat(plan, live)
}
