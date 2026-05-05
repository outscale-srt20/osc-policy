# METADATA
# id: OSC-OKS-006
# title: Cluster OKS sans tags de gouvernance
# description: |
#   Tags CostCenter / Project / Env / Owner manquants sur le cluster OKS.
#   Sans ces tags, impossible d'attribuer le coût ou de tracer la propriété
#   du cluster en cas d'incident.
# severity: MEDIUM
# category: compliance
# profile: compliance
# resource_types:
#   - outscale_oks_cluster
# source: plan,live
# remediation: |
#   Ajouter les tags CostCenter, Project, Env, Owner à la création du
#   cluster (champ tags dans outscale_oks_cluster).
# compliance:
#   iso_27001_2022: ["A.5.9", "A.5.12"]
package compliance.outscale.oks_006

import rego.v1
import data.lib.modules

required_tags := {"CostCenter", "Project", "Env", "Owner"}

deny contains msg if {
    some r in all_clusters
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
    "rule_id": "OSC-OKS-006",
    "rule_title": "Cluster OKS sans tags de gouvernance",
    "severity": "MEDIUM",
    "category": "compliance",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Cluster OKS '%s' — tags manquants: %v", [r.address, missing]),
    "remediation": "Ajouter les tags CostCenter, Project, Env, Owner.",
})

all_clusters := modules.resources_of_type("outscale_oks_cluster")
