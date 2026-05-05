# METADATA
# id: OSC-OKS-004
# title: Cluster OKS sans protection contre la suppression API
# description: |
#   disable_api_termination = false (défaut) permet de supprimer le cluster
#   par un simple appel API. En production, activer cette protection évite
#   les suppressions accidentelles ou malveillantes.
# severity: MEDIUM
# category: security
# profile: security
# resource_types:
#   - outscale_oks_cluster
# source: plan,live
# remediation: |
#   Activer disable_api_termination = true sur les clusters production.
#   La suppression nécessite alors de désactiver d'abord cette protection.
# noncompliant_example: |
#   resource "outscale_oks_cluster" "c" { name = "prod" }
# compliant_example: |
#   resource "outscale_oks_cluster" "c" {
#     name                    = "prod"
#     disable_api_termination = true
#   }
# compliance:
#   anssi_bp_028: ["R63"]
package security.outscale.oks_004

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_clusters
    not protected(r)
    not non_prod(r)
    msg := build(r)
}

protected(r) if {
    r.values.disable_api_termination == true
}

non_prod(r) if {
    tags := r.values.tags
    val := tags.env
    lower(val) in {"dev", "staging", "test", "poc", "sandbox"}
}
non_prod(r) if {
    tags := r.values.tags
    val := tags.Env
    lower(val) in {"dev", "staging", "test", "poc", "sandbox"}
}

build(r) := json.marshal({
    "rule_id": "OSC-OKS-004",
    "rule_title": "Cluster OKS sans protection contre la suppression API",
    "severity": "MEDIUM",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Cluster OKS '%s' a disable_api_termination = false (par défaut) — suppression API directe possible", [r.address]),
    "remediation": "Activer disable_api_termination = true en production. Tag env=dev|staging|test|poc pour ignorer.",
})

all_clusters := modules.resources_of_type("outscale_oks_cluster")
