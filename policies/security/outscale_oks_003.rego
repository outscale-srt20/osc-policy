# METADATA
# id: OSC-OKS-003
# title: Control plane OKS mono-AZ (cp_multi_az = false)
# description: |
#   cp_multi_az = false confine le control plane Kubernetes à une seule
#   sous-région. Si l'AZ tombe, le control plane est indisponible. Pour
#   production, activer cp_multi_az.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_oks_cluster
# source: plan,live
# remediation: |
#   Activer cp_multi_az = true à la création du cluster (non modifiable
#   ensuite sur la plupart des offres). Re-créer le cluster si nécessaire.
# noncompliant_example: |
#   resource "outscale_oks_cluster" "c" {
#     cp_multi_az = false
#   }
# compliant_example: |
#   resource "outscale_oks_cluster" "c" {
#     cp_multi_az = true
#   }
# compliance:
#   iso_27001_2022: ["A.8.14"]
package security.outscale.oks_003

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_clusters
    r.values.cp_multi_az == false
    # Skip if the cluster is explicitly tagged as non-prod (dev/staging/test/poc)
    not non_prod(r)
    msg := build(r)
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
    "rule_id": "OSC-OKS-003",
    "rule_title": "Control plane OKS mono-AZ",
    "severity": "HIGH",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Cluster OKS '%s' a cp_multi_az = false — tombe avec son AZ", [r.address]),
    "remediation": "Activer cp_multi_az = true (recreate cluster si déjà déployé). Tag env=dev|staging|test|poc pour ignorer.",
})

all_clusters := modules.resources_of_type("outscale_oks_cluster")
