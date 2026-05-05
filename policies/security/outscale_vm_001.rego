# METADATA
# id: OSC-VM-001
# title: VM sans security group
# description: |
#   Une VM démarrée sans security group n'applique aucun filtrage réseau et
#   hérite du SG par défaut, souvent très permissif. Tout service exposé sur
#   la VM est alors joignable par tout autre hôte de la région ou d'Internet.
# severity: CRITICAL
# category: security
# profile: security
# resource_types:
#   - outscale_vm
# source: plan,live
# remediation: |
#   1. Créer un security group dédié documenté
#   2. Référencer son ID dans `security_group_ids` de la VM
#   3. Ne jamais laisser la VM sur le SG `default`
# noncompliant_example: |
#   resource "outscale_vm" "web" {
#     image_id = "ami-12345678"
#     vm_type  = "tinav5.c2r4p1"
#   }
# compliant_example: |
#   resource "outscale_vm" "web" {
#     image_id           = "ami-12345678"
#     vm_type            = "tinav5.c2r4p1"
#     security_group_ids = [outscale_security_group.web.id]
#   }
# references: []
# compliance:
#   anssi_bp_028: ["R37", "R65"]
#   secnumcloud_3_2: ["13.1", "13.3"]
#   cis_controls_v8: ["4.4"]
#   iso_27001_2022: ["A.8.20"]
#   iso_27017: ["CLD.9.5.2"]
package security.outscale.vm_001

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_vms
    not has_sg(r)
    msg := json.marshal({
        "rule_id":          "OSC-VM-001",
        "rule_title":       "VM sans security group",
        "severity":         "CRITICAL",
        "category":         "security",
        "resource_id":      object.get(r, "id", r.address),
        "resource_type":    r.type,
        "resource_address": r.address,
        "message":          "VM démarrée sans security group attaché",
        "remediation":      "Attacher un security group restrictif à la VM.",
    })
}

has_sg(r) if {
    count(r.values.security_group_ids) > 0
}
has_sg(r) if {
    count(r.values.security_groups) > 0
}

all_vms := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_vm"]
    live := [r | some r in modules.live_resources; r.type == "outscale_vm"]
    out := array.concat(plan, live)
}
