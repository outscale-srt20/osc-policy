# METADATA
# id: OSC-FIN-002
# title: Volume BSU orphelin (non attaché)
# description: |
#   Un volume BSU non attaché continue d'être facturé au Go/mois selon
#   son type. Typiquement 0,044 €/Go/mois pour un gp2.
# severity: MEDIUM
# category: finops
# profile: finops
# resource_types:
#   - outscale_volume
# source: live
# remediation: |
#   Supprimer le volume ou l'attacher à une VM.
# noncompliant_example: |
#   # Volume state=available > 7 jours
# compliant_example: |
#   # Volume attaché
# references: []
# compliance:
#   secnumcloud_3_2: ["8.2"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.9", "A.5.10"]
package finops.outscale.fin_002

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_volume"
    r.values.state == "available"
    count(object.get(r.values, "linked_volumes", [])) == 0
    size := object.get(r.values, "size", 0)
    volume_type := object.get(r.values, "volume_type", "gp2")
    price := object.get(data.catalog.volume_per_gb_month, volume_type, 0.044)
    cost := size * price
    msg := json.marshal({
        "rule_id": "OSC-FIN-002",
        "rule_title": "Volume BSU orphelin",
        "severity": "MEDIUM",
        "category": "finops",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": sprintf("Volume %v de %v Go non attaché", [volume_type, size]),
        "remediation": "Supprimer ou ré-attacher le volume.",
        "estimated_monthly_cost": cost,
        "potential_monthly_savings": cost,
    })
}
