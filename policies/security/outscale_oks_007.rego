# METADATA
# id: OSC-OKS-007
# title: Projet OKS avec CIDR trop large
# description: |
#   Un projet OKS définit un CIDR pour son réseau. Un /8 ou /12 réserve un
#   espace énorme et augmente les risques de chevauchement avec d'autres
#   réseaux (peering, VPN, on-prem). Préférer /16 ou /20.
# severity: MEDIUM
# category: security
# profile: security
# resource_types:
#   - outscale_oks_project
# source: plan,live
# remediation: |
#   Dimensionner le CIDR projet selon la capacité cible (nb workers x nb pods).
#   /16 (~65k IPs) est suffisant pour la plupart des clusters.
# compliance:
#   anssi_bp_028: ["R45"]
package security.outscale.oks_007

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_projects
    cidr := r.values.cidr
    is_too_large(cidr)
    msg := build(r, cidr)
}

is_too_large(cidr) if {
    parts := split(cidr, "/")
    count(parts) == 2
    prefix := to_number(parts[1])
    prefix < 16
}

build(r, cidr) := json.marshal({
    "rule_id": "OSC-OKS-007",
    "rule_title": "Projet OKS avec CIDR trop large",
    "severity": "MEDIUM",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Projet OKS '%s' a CIDR %s (préfixe < /16) — espace réservé excessif, risque de collision réseau", [r.address, cidr]),
    "remediation": "Redimensionner le CIDR projet à /16 ou plus restrictif.",
})

all_projects := modules.resources_of_type("outscale_oks_project")
