# METADATA
# id: OSC-OOS-001
# title: Bucket OOS accessible publiquement
# description: |
#   Un bucket Object Storage (OOS) avec ACL public-read ou public-read-write
#   expose ses objets à Internet. Cette erreur est fréquente et source de
#   fuites massives.
# severity: CRITICAL
# category: security
# profile: security
# resource_types:
#   - outscale_oos
# source: live
# remediation: |
#   Passer l'ACL en private, configurer une politique restreinte,
#   et utiliser des URL pré-signées pour les accès temporaires.
# noncompliant_example: |
#   # ACL: public-read ou public-read-write
# compliant_example: |
#   # ACL: private
# references:
#   - "CIS Benchmark 2.1"
# compliance:
#   anssi_bp_028: ["R1", "R65"]
#   secnumcloud_3_2: ["9.2", "13.1"]
#   cis_controls_v8: ["3.3", "3.11"]
#   iso_27001_2022: ["A.5.15", "A.8.3", "A.8.11"]
#   iso_27017: ["CLD.8.1.5", "CLD.9.5.1"]
package security.outscale.oos_001

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_oos"
    acl := object.get(r.values, "acl", "")
    public_acl(acl)
    msg := json.marshal({
        "rule_id": "OSC-OOS-001",
        "rule_title": "Bucket OOS public",
        "severity": "CRITICAL",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": sprintf("Bucket OOS avec ACL '%v' — accessible publiquement", [acl]),
        "remediation": "Passer l'ACL en private.",
    })
}

public_acl(acl) if acl == "public-read"
public_acl(acl) if acl == "public-read-write"
