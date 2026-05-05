# METADATA
# id: OSC-FIN-001
# title: EIP orpheline (non attachée)
# description: |
#   Une Elastic IP non attachée est facturée chaque heure. Le coût mensuel
#   est de l'ordre de 3,60 €/EIP (catalogue par défaut).
# severity: MEDIUM
# category: finops
# profile: finops
# resource_types:
#   - outscale_public_ip
# source: live
# remediation: |
#   Attacher l'EIP à une VM/LBU/NAT ou la libérer si inutile.
# noncompliant_example: |
#   # EIP state=available depuis N jours
# compliant_example: |
#   # EIP attachée à une VM
# references: []
# compliance:
#   secnumcloud_3_2: ["8.2"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.9", "A.5.10"]
package finops.outscale.fin_001

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_public_ip"
    not r.values.vm_id
    not r.values.nic_id
    cost := data.catalog.eip_per_month
    msg := json.marshal({
        "rule_id": "OSC-FIN-001",
        "rule_title": "EIP orpheline",
        "severity": "MEDIUM",
        "category": "finops",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "Elastic IP non attachée — coût pur",
        "remediation": "Attacher l'EIP ou la libérer.",
        "estimated_monthly_cost": cost,
        "potential_monthly_savings": cost,
    })
}
