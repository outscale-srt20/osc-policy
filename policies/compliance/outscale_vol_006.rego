# METADATA
# id: OSC-VOL-006
# title: Volume BSU en usage sans snapshot récent (< 7 jours)
# description: |
#   Un volume BSU "in-use" (attaché à une VM active) sans snapshot dans
#   les 7 derniers jours indique un défaut de sauvegarde. En cas de
#   corruption, perte VM ou ransomware, données perdues au-delà du dernier
#   snapshot.
# severity: HIGH
# category: compliance
# profile: compliance
# resource_types:
#   - outscale_volume
# source: live
# remediation: |
#   1. Mettre en place un snapshot quotidien automatisé (CronJob qui
#      appelle CreateSnapshot, ou opérateur Velero pour OKS).
#   2. Tester la restauration trimestriellement.
#   3. Stocker une copie hors-AZ via export OOS pour la règle 3-2-1.
# references:
#   - "ANSSI-BP-028 R69 — Politique de sauvegarde"
# compliance:
#   anssi_bp_028: ["R69", "R70"]
#   secnumcloud_3_2: ["12.3"]
#   cis_controls_v8: ["11.1", "11.4"]
#   iso_27001_2022: ["A.8.13"]
package compliance.outscale.vol_006

import rego.v1
import data.lib.modules

# 7 days in nanoseconds.
recent_window_ns := 7 * 24 * 3600 * 1000 * 1000 * 1000

deny contains msg if {
    some v in all_volumes
    v.values.state == "in-use"
    not has_recent_snapshot(v.values.volume_id)
    msg := build(v)
}

has_recent_snapshot(volume_id) if {
    some s in modules.resources_of_type("outscale_snapshot")
    s.values.volume_id == volume_id
    is_recent(s.values.creation_date)
}

is_recent(date_str) if {
    is_string(date_str)
    snap_ns := time.parse_rfc3339_ns(date_str)
    age := time.now_ns() - snap_ns
    age <= recent_window_ns
}

build(v) := json.marshal({
    "rule_id": "OSC-VOL-006",
    "rule_title": "Volume BSU en usage sans snapshot récent",
    "severity": "HIGH",
    "category": "security",
    "resource_id": object.get(v, "id", v.address),
    "resource_type": v.type,
    "resource_address": v.address,
    "message": sprintf("Volume '%s' (state=in-use) sans snapshot dans les 7 derniers jours — risque de perte de données", [v.address]),
    "remediation": "Mettre en place un snapshot quotidien automatisé. Tester la restauration trimestriellement.",
})

all_volumes := modules.resources_of_type("outscale_volume")
