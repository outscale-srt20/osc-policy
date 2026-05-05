# METADATA
# id: OSC-OKS-008
# title: Cluster OKS sur version Kubernetes obsolète
# description: |
#   Kubernetes upstream maintient ~3 versions mineures en parallèle (~14 mois
#   de support par version). Une version trop ancienne ne reçoit plus de
#   patches sécurité.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_oks_cluster
# source: plan,live
# remediation: |
#   Planifier l'upgrade vers une version supportée. La méthode recommandée
#   sur OKS est le remplacement de nodepool (pas l'upgrade in-place).
# noncompliant_example: |
#   resource "outscale_oks_cluster" "c" { version = "1.28" }
# compliant_example: |
#   resource "outscale_oks_cluster" "c" { version = "1.32" }
# compliance:
#   anssi_bp_028: ["R10"]
#   secnumcloud_3_2: ["12.4"]
package security.outscale.oks_008

import rego.v1
import data.lib.modules

# Minimum supported minor version. Update annually as Kubernetes versions are
# deprecated by upstream and OKS support catalog.
min_supported_minor := 30

deny contains msg if {
    some r in all_clusters
    version := r.values.version
    is_obsolete(version)
    msg := build(r, version)
}

is_obsolete(version) if {
    parts := split(version, ".")
    count(parts) >= 2
    minor := to_number(parts[1])
    minor < min_supported_minor
}

build(r, version) := json.marshal({
    "rule_id": "OSC-OKS-008",
    "rule_title": "Cluster OKS sur version Kubernetes obsolète",
    "severity": "HIGH",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Cluster OKS '%s' sur Kubernetes %s — version inférieure à 1.%d (minimum supporté upstream)", [r.address, version, min_supported_minor]),
    "remediation": "Planifier l'upgrade vers une version Kubernetes supportée. Préférer le remplacement de nodepool.",
})

all_clusters := modules.resources_of_type("outscale_oks_cluster")
