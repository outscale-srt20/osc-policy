# METADATA
# id: OSC-FIN-003
# title: VM stoppée depuis longtemps
# description: |
#   Une VM stoppée depuis longtemps continue de facturer ses volumes BSU
#   attachés ainsi que les EIP associées. Souvent un oubli.
# severity: MEDIUM
# category: finops
# profile: finops
# resource_types:
#   - outscale_vm
# source: live
# remediation: |
#   Supprimer la VM et ses volumes si inutiles, ou la redémarrer.
# noncompliant_example: |
#   # VM state=stopped depuis 30+ jours
# compliant_example: |
#   # VM running ou supprimée
# references: []
# compliance:
#   secnumcloud_3_2: ["8.2"]
#   cis_controls_v8: ["1.1", "5.3"]
#   iso_27001_2022: ["A.5.9", "A.5.10"]
package finops.outscale.fin_003

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_vm"
    r.values.state == "stopped"
    days := object.get(r.values, "stopped_days", 0)
    days > 30
    msg := json.marshal({
        "rule_id": "OSC-FIN-003",
        "rule_title": "VM stoppée depuis longtemps",
        "severity": "MEDIUM",
        "category": "finops",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": sprintf("VM stoppée depuis %v jours", [days]),
        "remediation": "Supprimer la VM si elle n'est plus utile.",
    })
}
