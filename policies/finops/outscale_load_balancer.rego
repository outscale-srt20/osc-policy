# METADATA
# id: OSC-FIN-004
# title: VM sur-provisionnée
# description: |
#   Une VM avec CPU moyen < 10% ou RAM < 30% sur 7 jours est sur-provisionnée.
#   Un rightsizing permet d'économiser jusqu'à 50% du coût horaire.
# severity: LOW
# category: finops
# profile: finops
# resource_types:
#   - outscale_vm
# source: live
# remediation: |
#   Migrer vers une VM plus petite (un cran de gamme en dessous).
# noncompliant_example: |
#   # VM c8r16p1 avec CPU moyen 5% sur 7j
# compliant_example: |
#   # VM c4r8p1 (taille adaptée à la charge)
# references: []
# compliance:
#   secnumcloud_3_2: ["8.2"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.10", "A.8.9"]
package finops.outscale.fin_004

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_vm"
    metrics := object.get(r.values, "metrics", {})
    avg_cpu := object.get(metrics, "avg_cpu_7d", 100)
    avg_cpu < data.catalog.thresholds.cpu_rightsizing
    msg := json.marshal({
        "rule_id": "OSC-FIN-004",
        "rule_title": "VM sur-provisionnée",
        "severity": "LOW",
        "category": "finops",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": sprintf("VM avec CPU moyen %v%% sur 7 jours — candidate au rightsizing", [avg_cpu]),
        "remediation": "Réduire la taille de la VM.",
    })
}
