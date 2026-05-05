# METADATA
# id: OSC-OOS-006
# title: Bucket OOS sans tags de gouvernance complets
# description: |
#   Tags CostCenter / Project / Env / Owner manquants sur le bucket OOS.
#   OSC-OOS-003 ne vérifie que le tag Name ; cette règle complète en
#   exigeant les 4 tags de gouvernance permettant la ventilation FinOps
#   et l'attribution de la propriété.
# severity: MEDIUM
# category: compliance
# profile: compliance
# resource_types:
#   - outscale_oos
# source: live
# remediation: |
#   aws s3api put-bucket-tagging --endpoint-url https://oos.<region>.outscale.com \
#     --bucket <name> --tagging 'TagSet=[
#       {Key=CostCenter,Value=cc-1234},
#       {Key=Project,Value=site-vitrine},
#       {Key=Env,Value=prod},
#       {Key=Owner,Value=team-web}
#     ]'
# compliance:
#   iso_27001_2022: ["A.5.9", "A.5.12"]
package compliance.outscale.oos_006

import rego.v1
import data.lib.modules

required_tags := {"CostCenter", "Project", "Env", "Owner"}

deny contains msg if {
    some r in all_buckets
    missing := required_tags - tag_keys(r)
    count(missing) > 0
    msg := build(r, missing)
}

tag_keys(r) := keys if {
    keys := {k | some k, _ in r.values.tags}
}
tag_keys(r) := set() if {
    not r.values.tags
}

build(r, missing) := json.marshal({
    "rule_id": "OSC-OOS-006",
    "rule_title": "Bucket OOS sans tags de gouvernance",
    "severity": "MEDIUM",
    "category": "compliance",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Bucket OOS '%s' — tags manquants: %v", [r.address, missing]),
    "remediation": "Ajouter les tags CostCenter, Project, Env, Owner.",
})

all_buckets := modules.resources_of_type("outscale_oos")
