# METADATA
# id: OSC-VM-003
# title: VM avec boot_mode=legacy (préférer UEFI)
# description: |
#   Les VMs démarrées en boot_mode=legacy ne bénéficient pas des protections
#   UEFI (Secure Boot, mesures TPM). Préférer UEFI pour les workloads modernes.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_vm
# source: plan,live
# remediation: |
#   Remplacer `boot_mode = "legacy"` par `boot_mode = "uefi"`.
# noncompliant_example: |
#   resource "outscale_vm" "vm" {
#     boot_mode = "legacy"
#   }
# compliant_example: |
#   resource "outscale_vm" "vm" {
#     boot_mode = "uefi"
#   }
# references: []
# compliance:
#   anssi_bp_028: ["R37", "R40"]
#   secnumcloud_3_2: ["20.1"]
#   cis_controls_v8: ["4.8"]
#   iso_27001_2022: ["A.8.9"]
#   iso_27017: ["CLD.9.5.2"]
package security.outscale.vm_003

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_vms
    r.values.boot_mode == "legacy"
    msg := json.marshal({
        "rule_id": "OSC-VM-003",
        "rule_title": "VM en boot_mode=legacy",
        "severity": "HIGH",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "VM configurée en boot_mode=legacy, préférer uefi",
        "remediation": "Passer la VM en boot_mode=uefi.",
    })
}

all_vms := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_vm"]
    live := [r | some r in modules.live_resources; r.type == "outscale_vm"]
    out := array.concat(plan, live)
}
