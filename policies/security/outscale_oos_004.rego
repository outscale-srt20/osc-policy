# METADATA
# id: OSC-OOS-004
# title: Bucket OOS avec policy publique (Principal "*")
# description: |
#   Une bucket policy contenant Effect: Allow + Principal: "*" autorise
#   tout le monde (y compris non-authentifié) à effectuer les actions
#   listées. C'est l'un des vecteurs #1 de data breach cloud (Capital One,
#   Verizon, Accenture). L'ACL public-read est détecté par OSC-OOS-001 ;
#   cette règle complète en analysant la bucket policy.
# severity: CRITICAL
# category: security
# profile: security
# resource_types:
#   - outscale_oos
# source: live
# remediation: |
#   1. Lister les statements problématiques :
#      aws s3api get-bucket-policy --endpoint-url https://oos.<region>.outscale.com \
#        --bucket <name> --query Policy --output text | jq
#   2. Soit supprimer la policy si pas nécessaire :
#      aws s3api delete-bucket-policy --endpoint-url ... --bucket <name>
#   3. Soit restreindre Principal à un compte/role/user précis (ARN explicite).
#   4. Pour servir du contenu public : utiliser CDN avec signed URLs, bucket origin privé.
# noncompliant_example: |
#   {
#     "Statement": [{
#       "Effect": "Allow",
#       "Principal": "*",
#       "Action": "s3:GetObject",
#       "Resource": "arn:aws:s3:::my-bucket/*"
#     }]
#   }
# compliant_example: |
#   {
#     "Statement": [{
#       "Effect": "Allow",
#       "Principal": {"AWS": "arn:aws:iam::123456789012:role/my-role"},
#       "Action": "s3:GetObject",
#       "Resource": "arn:aws:s3:::my-bucket/*"
#     }]
#   }
# references:
#   - "OWASP Cloud-Native Application Security Top 10 — CNAS-2"
# compliance:
#   anssi_bp_028: ["R12"]
#   secnumcloud_3_2: ["12.1"]
#   cis_controls_v8: ["3.3"]
#   iso_27001_2022: ["A.5.10", "A.8.20"]
package security.outscale.oos_004

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_buckets
    r.values.policy_public == true
    msg := build(r)
}

build(r) := json.marshal({
    "rule_id": "OSC-OOS-004",
    "rule_title": "Bucket OOS avec policy publique (Principal \"*\")",
    "severity": "CRITICAL",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Bucket OOS '%s' a une bucket policy avec Principal '*' (Allow) — accessible sans auth", [r.address]),
    "remediation": "Restreindre Principal à un ARN précis (compte/role/user). Si pas nécessaire, delete-bucket-policy.",
})

all_buckets := modules.resources_of_type("outscale_oos")
