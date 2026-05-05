# METADATA
# id: OSC-VM-008
# title: VM avec secret en clair dans user_data
# description: |
#   user_data est lisible via l'IMDS (http://169.254.169.254/latest/user-data)
#   par tout processus root sur la VM, et par tout pod hostNetwork sur OKS.
#   Stocker des access keys, clés privées ou mots de passe dans user_data
#   les expose à toute compromission applicative ou supply chain.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_vm
# source: plan,live
# remediation: |
#   1. Retirer immédiatement le secret de user_data.
#   2. Rotationner le secret compromis (l'IMDS ne tracke pas les lectures
#      passées, considérer le secret comme exfiltré).
#   3. Utiliser un mécanisme runtime : Vault + sidecar, External Secrets
#      Operator, ou cred-provider Kubelet pour OKS.
# noncompliant_example: |
#   resource "outscale_vm" "app" {
#     # /!\ AKIAEXAMPLE0000000000 is a placeholder, never commit a real key
#     user_data = base64encode("export OSC_ACCESS_KEY=AKIAEXAMPLE0000000000")
#   }
# compliant_example: |
#   resource "outscale_vm" "app" {
#     user_data = base64encode(file("cloud-init-without-secrets.yml"))
#   }
# references:
#   - "OWASP Cloud-Native Application Security Top 10 — CNAS-9"
# compliance:
#   anssi_bp_028: ["R31", "R79"]
#   secnumcloud_3_2: ["19.1", "19.2"]
#   cis_controls_v8: ["3.11", "5.2"]
#   iso_27001_2022: ["A.8.24"]
package security.outscale.vm_008

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_vms
    raw := user_data(r)
    raw != ""
    found := first_secret_pattern(raw)
    found != ""
    msg := build(r, found)
}

# Reads user_data, decoding base64 if needed (live API returns base64,
# Terraform plan may return raw or base64 depending on the resource).
user_data(r) := raw if {
    raw := r.values.user_data
    is_string(raw)
    not is_base64(raw)
}
user_data(r) := decoded if {
    raw := r.values.user_data
    is_string(raw)
    is_base64(raw)
    decoded := base64.decode(raw)
}

# Heuristic: only base64 chars and length divisible by 4.
is_base64(s) if {
    regex.match(`^[A-Za-z0-9+/]+={0,2}$`, s)
    count(s) % 4 == 0
}

first_secret_pattern(s) := "AWS/Outscale Access Key (AKIA...)" if {
    regex.match(`AKIA[0-9A-Z]{16}`, s)
}
first_secret_pattern(s) := "PRIVATE KEY block" if {
    contains(s, "BEGIN ")
    contains(s, "PRIVATE KEY")
}
first_secret_pattern(s) := "password=... assignment" if {
    regex.match(`(?i)pass(word)?\s*[:=]\s*[^\s\n"']{6,}`, s)
}
first_secret_pattern(s) := "secret_key= assignment" if {
    regex.match(`(?i)(secret|api)_?key\s*[:=]\s*[^\s\n"']{8,}`, s)
}
first_secret_pattern(s) := "Bearer token" if {
    regex.match(`(?i)Bearer\s+[A-Za-z0-9._-]{20,}`, s)
}

build(r, what) := json.marshal({
    "rule_id": "OSC-VM-008",
    "rule_title": "VM avec secret en clair dans user_data",
    "severity": "HIGH",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("VM '%s' a un secret détecté dans user_data : %s", [r.address, what]),
    "remediation": "Retirer le secret de user_data, le rotationner (considéré exfiltré), et utiliser Vault/ESO pour l'injection runtime.",
})

all_vms := modules.resources_of_type("outscale_vm")
