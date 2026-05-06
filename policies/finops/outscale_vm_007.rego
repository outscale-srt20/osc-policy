# METADATA
# id: OSC-VM-007
# title: VM stoppée sans tag ExpiresAt (zombie potentiel)
# description: |
#   Une VM stoppée sans tag ExpiresAt pourrait rester indéfiniment et générer
#   des coûts de stockage BSU associés. Le tag ExpiresAt permet aux outils
#   d'automatisation de supprimer les ressources expirées.
# severity: LOW
# category: finops
# profile: finops
# resource_types:
#   - outscale_vm
# source: live
# remediation: |
#   Ajouter un tag `ExpiresAt` au format ISO 8601 (ex: 2026-12-31T23:59:59Z)
#   ou démarrer/supprimer la VM.
# noncompliant_example: |
#   # VM state=stopped sans tag ExpiresAt
# compliant_example: |
#   tags { key = "ExpiresAt" value = "2026-12-31T23:59:59Z" }
# references: []
# compliance:
#   secnumcloud_3_2: ["8.1", "8.2"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.9", "A.5.10"]
package finops.outscale.vm_007

import rego.v1
import data.lib.modules
import data.lib.utils

deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_vm"
    r.values.state == "stopped"
    not utils.has_tag(object.get(r.values, "tags", []), "ExpiresAt")
    msg := json.marshal({
        "rule_id": "OSC-VM-007",
        "rule_title": "VM stoppée sans ExpiresAt",
        "severity": "LOW",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "VM stoppée sans tag ExpiresAt — potentiellement zombie",
        "remediation": "Ajouter un tag ExpiresAt ou supprimer la VM.",
    })
}
