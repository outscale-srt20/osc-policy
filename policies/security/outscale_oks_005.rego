# METADATA
# id: OSC-OKS-005
# title: Maintenance automatique Kubernetes désactivée
# description: |
#   auto_maintenances pilote les fenêtres de mise à jour Kubernetes (minor
#   et patch). Désactiver ces maintenances laisse le cluster sur une version
#   non patchée (CVEs kubernetes, kubelet, runtime).
# severity: MEDIUM
# category: security
# profile: security
# resource_types:
#   - outscale_oks_cluster
# source: plan,live
# remediation: |
#   Activer minor_upgrade_maintenance.enabled et patch_upgrade_maintenance.enabled.
#   Configurer une fenêtre hors heures critiques (ex: dimanche matin).
# noncompliant_example: |
#   resource "outscale_oks_cluster" "c" {
#     auto_maintenances = {
#       patch_upgrade_maintenance = { enabled = false }
#     }
#   }
# compliance:
#   anssi_bp_028: ["R10", "R65"]
#   secnumcloud_3_2: ["12.1"]
package security.outscale.oks_005

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_clusters
    not patch_enabled(r)
    msg := build(r, "patch_upgrade_maintenance")
}
deny contains msg if {
    some r in all_clusters
    not minor_enabled(r)
    msg := build(r, "minor_upgrade_maintenance")
}

# Default behaviour is "enabled" if the field is absent in the response,
# but we treat absence as "explicit configuration missing" only when the
# auto_maintenances block exists with the upgrade key set to false.
patch_enabled(r) if {
    r.values.auto_maintenances.patch_upgrade_maintenance.enabled == true
}
patch_enabled(r) if {
    not r.values.auto_maintenances.patch_upgrade_maintenance
}

minor_enabled(r) if {
    r.values.auto_maintenances.minor_upgrade_maintenance.enabled == true
}
minor_enabled(r) if {
    not r.values.auto_maintenances.minor_upgrade_maintenance
}

build(r, kind) := json.marshal({
    "rule_id": "OSC-OKS-005",
    "rule_title": "Maintenance Kubernetes désactivée",
    "severity": "MEDIUM",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Cluster OKS '%s' a %s.enabled = false — version Kubernetes non patchée", [r.address, kind]),
    "remediation": "Activer auto_maintenances.{minor,patch}_upgrade_maintenance.enabled = true.",
})

all_clusters := modules.resources_of_type("outscale_oks_cluster")
