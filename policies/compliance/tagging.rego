# METADATA
# id: OSC-TAG-001
# title: Tags CostCenter/Project/Env/Owner manquants
# description: |
#   Les ressources facturables doivent porter les tags CostCenter, Project,
#   Env et Owner pour permettre la répartition analytique des coûts.
# severity: MEDIUM
# category: compliance
# profile: compliance
# resource_types:
#   - outscale_vm
#   - outscale_volume
#   - outscale_load_balancer
#   - outscale_public_ip
#   - outscale_oos
# source: plan,live
# remediation: |
#   Ajouter les quatre tags obligatoires (CostCenter, Project, Env, Owner)
#   sur les ressources facturables.
# noncompliant_example: |
#   resource "outscale_vm" "v" { tags { key = "Name" value = "web" } }
# compliant_example: |
#   resource "outscale_vm" "v" {
#     tags { key = "Name"       value = "web" }
#     tags { key = "Env"        value = "prod" }
#     tags { key = "CostCenter" value = "42" }
#     tags { key = "Project"    value = "platform" }
#     tags { key = "Owner"      value = "team-sre" }
#   }
# references:
#   - "FinOps Foundation — Tagging Best Practices"
# compliance:
#   anssi_bp_028: ["R1"]
#   secnumcloud_3_2: ["19.3"]
#   cis_controls_v8: ["3.3"]
#   iso_27001_2022: ["A.5.15", "A.8.9"]
#   iso_27017: ["CLD.6.3.1"]
package compliance.outscale.tag_001

import rego.v1
import data.lib.modules
import data.lib.utils

billable_types := {
    "outscale_vm",
    "outscale_volume",
    "outscale_load_balancer",
    "outscale_public_ip",
    "outscale_oos",
}

required := ["CostCenter", "Project", "Env", "Owner"]

deny contains msg if {
    some r in billable_resources
    tags := object.get(r.values, "tags", [])
    missing := [t | some t in required; not utils.has_tag(tags, t)]
    count(missing) > 0
    msg := json.marshal({
        "rule_id": "OSC-TAG-001",
        "rule_title": "Tags de gouvernance manquants",
        "severity": "MEDIUM",
        "category": "compliance",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": sprintf("Tags manquants : %v", [concat(", ", missing)]),
        "remediation": sprintf("Ajouter les tags %v", [concat(", ", missing)]),
    })
}

billable_resources := out if {
    plan := [r | some r in modules.all_resources; r.type in billable_types]
    live := [r | some r in modules.live_resources; r.type in billable_types]
    out := array.concat(plan, live)
}
