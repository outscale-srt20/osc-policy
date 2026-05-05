# METADATA
# id: OSC-EIM-009
# title: Policy EIM avec NotAction ou NotResource (anti-pattern)
# description: |
#   NotAction et NotResource inversent la logique de la policy : tout est
#   autorisé SAUF la liste donnée. Ce pattern est très difficile à raisonner
#   et conduit régulièrement à des privilèges effectifs trop larges.
#   AWS recommande de l'éviter sauf cas très spécifiques documentés.
# severity: CRITICAL
# category: security
# profile: security
# resource_types:
#   - outscale_eim_policy
# source: plan,live
# remediation: |
#   Réécrire la policy avec des Action/Resource explicites en allowlist.
#   Si NotAction est strictement nécessaire (cas rare), documenter la
#   décision dans un ADR et restreindre à un Effect: Deny au lieu d'Allow.
# noncompliant_example: |
#   {
#     "Version": "2012-10-17",
#     "Statement": [{
#       "Effect": "Allow",
#       "NotAction": ["iam:*"],
#       "Resource": "*"
#     }]
#   }
# compliant_example: |
#   {
#     "Version": "2012-10-17",
#     "Statement": [{
#       "Effect": "Allow",
#       "Action": ["s3:GetObject", "s3:ListBucket"],
#       "Resource": "arn:aws:s3:::my-bucket/*"
#     }]
#   }
# references:
#   - "AWS IAM User Guide — Avoid NotAction with Effect: Allow"
# compliance:
#   anssi_bp_028: ["R12", "R13"]
#   secnumcloud_3_2: ["19.1"]
#   cis_controls_v8: ["6.8"]
#   iso_27001_2022: ["A.5.15", "A.8.2"]
package security.outscale.eim_009

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_policies
    body := r.values.document_body
    body != ""
    has_dangerous_inversion(body)
    msg := build(r)
}

has_dangerous_inversion(body) if {
    contains(body, "\"NotAction\"")
}
has_dangerous_inversion(body) if {
    contains(body, "\"NotResource\"")
}

build(r) := json.marshal({
    "rule_id": "OSC-EIM-009",
    "rule_title": "Policy EIM avec NotAction ou NotResource",
    "severity": "CRITICAL",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Policy EIM '%s' utilise NotAction ou NotResource — pattern d'inversion dangereux", [r.address]),
    "remediation": "Réécrire la policy en allowlist explicite (Action/Resource). NotAction acceptable uniquement avec Effect: Deny.",
})

all_policies := modules.resources_of_type("outscale_eim_policy")
