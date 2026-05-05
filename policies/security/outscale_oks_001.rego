# METADATA
# id: OSC-OKS-001
# title: API server OKS exposé à Internet (admin_whitelist contient 0.0.0.0/0 ou ::/0)
# description: |
#   admin_whitelist contrôle les IPs autorisées à appeler l'API Kubernetes
#   du cluster OKS. Une whitelist contenant 0.0.0.0/0 (ou ::/0) expose l'API
#   à l'Internet entier — un cert kubelet volé ou un kubeconfig fuité devient
#   exploitable depuis n'importe quelle IP du monde.
# severity: CRITICAL
# category: security
# profile: security
# resource_types:
#   - outscale_oks_cluster
# source: plan,live
# remediation: |
#   1. Restreindre admin_whitelist aux IPs précises (bastion, runners CI, VPN
#      d'entreprise) en notation CIDR /32 quand possible.
#   2. Supprimer toute entrée 0.0.0.0/0 ou ::/0.
#   3. Auditer périodiquement la liste pour retirer les IPs obsolètes.
# noncompliant_example: |
#   resource "outscale_oks_cluster" "c" {
#     name            = "prod"
#     admin_whitelist = ["0.0.0.0/0"]
#     # ...
#   }
# compliant_example: |
#   resource "outscale_oks_cluster" "c" {
#     name            = "prod"
#     admin_whitelist = ["10.0.0.5/32", "203.0.113.42/32"]
#     # ...
#   }
# references:
#   - "ANSSI-BP-028 R12"
# compliance:
#   anssi_bp_028: ["R12"]
#   secnumcloud_3_2: ["12.1"]
#   cis_controls_v8: ["4.4", "13.4"]
#   iso_27001_2022: ["A.8.20", "A.8.22"]
package security.outscale.oks_001

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_clusters
    some cidr in cidrs(r)
    open_to_world(cidr)
    msg := build(r, cidr)
}

cidrs(r) := wl if {
    wl := r.values.admin_whitelist
}

open_to_world(cidr) if {
    cidr == "0.0.0.0/0"
}
open_to_world(cidr) if {
    cidr == "::/0"
}

build(r, cidr) := json.marshal({
    "rule_id": "OSC-OKS-001",
    "rule_title": "API server OKS exposé à Internet",
    "severity": "CRITICAL",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Cluster OKS '%s' a admin_whitelist contenant %s — API Kubernetes exposée à l'Internet entier", [r.address, cidr]),
    "remediation": "Restreindre admin_whitelist aux IPs précises (bastion, runners CI, VPN). Supprimer 0.0.0.0/0 et ::/0.",
})

all_clusters := modules.resources_of_type("outscale_oks_cluster")
