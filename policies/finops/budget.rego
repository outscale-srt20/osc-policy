# METADATA
# id: OSC-FIN-005
# title: Dépassement de budget mensuel estimé
# description: |
#   Le coût mensuel estimé dépasse le budget défini via
#   input.budget.monthly_budget (ou 0 si non défini).
# severity: LOW
# category: finops
# profile: finops
# resource_types:
#   - budget
# source: plan,live
# remediation: |
#   Revoir les choix de VM/volumes ou augmenter le budget.
# noncompliant_example: |
#   # total_cost = 500 €, budget = 300 €
# compliant_example: |
#   # total_cost < budget
# references: []
# compliance:
#   secnumcloud_3_2: ["8.2"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.10"]
package finops.outscale.fin_005

import rego.v1

deny contains msg if {
    budget := input.budget.monthly_budget
    budget > 0
    total := input.budget.estimated_total
    total > budget
    msg := json.marshal({
        "rule_id": "OSC-FIN-005",
        "rule_title": "Dépassement de budget",
        "severity": "LOW",
        "category": "finops",
        "resource_id": "budget",
        "resource_type": "budget",
        "resource_address": "budget",
        "message": sprintf("Coût estimé %.2f € > budget %.2f €", [total, budget]),
        "remediation": "Revoir les ressources ou le budget.",
        "estimated_monthly_cost": total,
    })
}
