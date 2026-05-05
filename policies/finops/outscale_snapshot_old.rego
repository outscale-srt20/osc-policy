# METADATA
# id: OSC-FIN-006
# title: Snapshot BSU > 90 jours (politique de rétention probablement absente)
# description: |
#   Sans politique de rétention explicite, les snapshots s'accumulent
#   indéfiniment et le coût stockage croît linéairement. Un snapshot
#   > 90 jours est probablement obsolète (les snapshots récents suffisent
#   pour la restauration opérationnelle).
# severity: MEDIUM
# category: finops
# profile: finops
# resource_types:
#   - outscale_snapshot
# source: live
# remediation: |
#   1. Définir une politique de rétention explicite (ex: 7 quotidiens
#      + 4 hebdomadaires + 3 mensuels = 14 snapshots max par volume).
#   2. CronJob mensuel qui supprime les snapshots au-delà de la rétention.
#   3. Pour conformité longue durée (audits, RGPD), exporter vers OOS
#      Cold Storage avec lifecycle.
# compliance:
#   iso_27001_2022: ["A.5.10", "A.8.10"]
package finops.outscale.snapshot_old

import rego.v1
import data.lib.modules

# 90 days in nanoseconds.
old_threshold_ns := 90 * 24 * 3600 * 1000 * 1000 * 1000

deny contains msg if {
    some s in all_snapshots
    is_old(s.values.creation_date)
    msg := build(s)
}

is_old(date_str) if {
    is_string(date_str)
    snap_ns := time.parse_rfc3339_ns(date_str)
    age := time.now_ns() - snap_ns
    age > old_threshold_ns
}

build(s) := json.marshal({
    "rule_id": "OSC-FIN-006",
    "rule_title": "Snapshot BSU > 90 jours",
    "severity": "MEDIUM",
    "category": "finops",
    "resource_id": object.get(s, "id", s.address),
    "resource_type": s.type,
    "resource_address": s.address,
    "message": sprintf("Snapshot '%s' a plus de 90 jours — probablement hors politique de rétention", [s.address]),
    "remediation": "Mettre en place une politique de rétention (7d + 4w + 3m typique). Supprimer ou exporter vers OOS si conservation longue.",
})

all_snapshots := modules.resources_of_type("outscale_snapshot")
