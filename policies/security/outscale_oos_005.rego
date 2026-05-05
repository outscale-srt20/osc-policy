# METADATA
# id: OSC-OOS-005
# title: Bucket OOS sans politique de cycle de vie
# description: |
#   Sans lifecycle policy, les objets s'accumulent indéfiniment et :
#   - le coût stockage croît linéairement (FinOps),
#   - les versions anciennes (si versioning activé) explosent,
#   - les uploads multipart incomplets restent facturés.
#   Utile aussi pour la conformité RGPD (durée de conservation).
# severity: MEDIUM
# category: finops
# profile: finops
# resource_types:
#   - outscale_oos
# source: live
# remediation: |
#   Définir une lifecycle policy adaptée au use case du bucket. Exemples :
#
#   - Logs avec rétention 90 jours :
#     aws s3api put-bucket-lifecycle-configuration --endpoint-url ... \
#       --bucket <name> --lifecycle-configuration '{
#         "Rules": [{"ID":"expire-logs","Status":"Enabled",
#                    "Filter":{"Prefix":""},"Expiration":{"Days":90}}]
#       }'
#
#   - Bucket versionné, expirer les versions non-courantes après 30 jours +
#     supprimer les uploads multipart abandonnés après 7 jours.
# compliance:
#   iso_27001_2022: ["A.5.10"]
package finops.outscale.oos_005

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_buckets
    r.values.lifecycle_configured == false
    msg := build(r)
}

build(r) := json.marshal({
    "rule_id": "OSC-OOS-005",
    "rule_title": "Bucket OOS sans politique de cycle de vie",
    "severity": "MEDIUM",
    "category": "finops",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Bucket OOS '%s' sans lifecycle policy — risque accumulation/coût croissant", [r.address]),
    "remediation": "Définir une lifecycle policy adaptée (Expiration, NoncurrentVersionExpiration, AbortIncompleteMultipartUpload).",
})

all_buckets := modules.resources_of_type("outscale_oos")
