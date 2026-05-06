# METADATA
# id: OSC-SG-005
# title: Security group sans description
# description: |
#   Un security group sans description rend l'audit et la gouvernance difficiles.
#   Documentez la raison d'être du groupe pour aider la revue de sécurité.
# severity: MEDIUM
# category: compliance
# profile: compliance
# resource_types:
#   - outscale_security_group
# source: plan,live
# remediation: |
#   Ajouter un champ `description` précisant le rôle du security group
#   (quelle application, quel tier, quelle équipe).
# noncompliant_example: |
#   resource "outscale_security_group" "web" {
#     security_group_name = "web-sg"
#   }
# compliant_example: |
#   resource "outscale_security_group" "web" {
#     security_group_name = "web-sg"
#     description         = "SG pour les VMs web tier front (équipe Platform)"
#   }
# references: []
# compliance:
#   anssi_bp_028: ["R1"]
#   secnumcloud_3_2: ["8.1"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.9"]
package compliance.outscale.sg_005

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_sgs
    not r.values.description
    msg := build(r)
}
deny contains msg if {
    some r in all_sgs
    r.values.description == ""
    msg := build(r)
}

build(r) := json.marshal({
    "rule_id":          "OSC-SG-005",
    "rule_title":       "Security group sans description",
    "severity":         "MEDIUM",
    "category":         "security",
    "resource_id":      object.get(r, "id", r.address),
    "resource_type":    r.type,
    "resource_address": r.address,
    "message":          "Security group sans description documentée",
    "remediation":      "Ajouter une description claire au security group.",
})

all_sgs := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_security_group"]
    live := [r | some r in modules.live_resources; r.type == "outscale_security_group"]
    out := array.concat(plan, live)
}
