# METADATA
# id: OSC-OKS-002
# title: Control plane OKS mono-master (SPOF)
# description: |
#   control_planes = "cp.mono.master" déploie un seul master Kubernetes.
#   En cas de panne du master ou de l'AZ, le control plane est inaccessible :
#   pas de scaling, pas de healing, pas de déploiement (les workloads existants
#   continuent à tourner). À éviter en production.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_oks_cluster
# source: plan,live
# remediation: |
#   Utiliser un control plane multi-master (ex: cp.3.masters.small) et activer
#   cp_multi_az = true pour répartir les masters entre sous-régions.
# noncompliant_example: |
#   resource "outscale_oks_cluster" "c" {
#     control_planes = "cp.mono.master"
#   }
# compliant_example: |
#   resource "outscale_oks_cluster" "c" {
#     control_planes = "cp.3.masters.small"
#     cp_multi_az    = true
#   }
# references:
#   - "AWS Well-Architected Reliability Pillar"
# compliance:
#   anssi_bp_028: ["R69"]
#   iso_27001_2022: ["A.8.14"]
package security.outscale.oks_002

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_clusters
    r.values.control_planes == "cp.mono.master"
    msg := build(r)
}

build(r) := json.marshal({
    "rule_id": "OSC-OKS-002",
    "rule_title": "Control plane OKS mono-master",
    "severity": "HIGH",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Cluster OKS '%s' utilise cp.mono.master — single point of failure", [r.address]),
    "remediation": "Migrer vers cp.3.masters.small (ou plus) avec cp_multi_az = true.",
})

all_clusters := modules.resources_of_type("outscale_oks_cluster")
