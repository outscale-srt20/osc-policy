# osc-policy

> Scanner **policy-as-code** de sécurité, conformité et FinOps pour
> [Outscale](https://outscale.com/). Analyse les **plans Terraform** avant
> déploiement et les **ressources live** via l'API Outscale après coup.

Moteur de règles [**OPA**](https://www.openpolicyagent.org/) embarqué (SDK Go,
pas de binaire externe). Policies écrites en **Rego v1**. Rendu terminal
inspiré de `checkov` / `tfsec`, exports SARIF / JUnit / JSON / Markdown.

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Utilisation de la CLI](#utilisation-de-la-cli)
  - [`osc-policy scan plan`](#osc-policy-scan-plan)
  - [`osc-policy scan live`](#osc-policy-scan-live)
  - [`osc-policy scan all`](#osc-policy-scan-all)
  - [`osc-policy explain`](#osc-policy-explain)
  - [`osc-policy init`](#osc-policy-init)
  - [`osc-policy fix`](#osc-policy-fix)
  - [`osc-policy suppress`](#osc-policy-suppress)
  - [`osc-policy diff`](#osc-policy-diff)
  - [`osc-policy report`](#osc-policy-report)
  - [`osc-policy rules list`](#osc-policy-rules-list)
  - [`osc-policy rules test`](#osc-policy-rules-test)
  - [`osc-policy docs generate`](#osc-policy-docs-generate)
  - [`osc-policy completion`](#osc-policy-completion)
- [Formats de sortie](#formats-de-sortie)
- [Scoring A–G](#scoring-ag)
- [Conformité multi-framework](#conformité-multi-framework)
- [Codes de sortie](#codes-de-sortie)
- [Extensibilité (policies custom)](#extensibilité-policies-custom)
- [Intégration CI/CD](#intégration-cicd)
- [Développement](#développement)
- [Licence](#licence)

---

## Fonctionnalités

- **Deux modes de scan** :
  - `scan plan` — analyse un fichier `terraform plan.json` (ou OpenTofu)
    avant déploiement.
  - `scan live` — analyse les ressources existantes via l'API Outscale
    (compatible `~/.osc/config.json`).
- **71 règles prêtes à l'emploi** couvrant VM, Security Group, Volume, Net,
  Load Balancer, Snapshot, VPN, EIM (policies), API access rules, Access Key,
  Keypair, Object Storage (OOS), Outscale Kubernetes Service (OKS), plus
  FinOps (EIP orpheline, volume non attaché, budget, rightsizing) et
  compliance (tags, chiffrement, journalisation).
- **Scoring A–G** par scan et par service (VM, SG, VOL, …), avec plafond
  CRITICAL à 45, et seuil de grade minimal via `--min-grade`.
- **Conformité multi-framework** : chaque règle est tagguée avec les contrôles
  qu'elle couvre (ANSSI-BP-028, SecNumCloud 3.2, CIS Controls v8,
  ISO 27001:2022, ISO 27017). Catalogue embarqué extensible.
- **5 formats de sortie** : terminal riche, JSON, SARIF 2.1.0 (propriétés
  custom avec le score), JUnit XML, Markdown.
- **UX orientée action** :
  - `explain` — documentation complète d'une règle (description, exemples, remédiation).
  - `init` — wizard interactif pour générer `.osc-policy.yaml`.
  - `fix` — patch Terraform ou commande oapi-cli prête à copier-coller (dry-run).
  - `suppress` — suppression documentée d'un finding avec raison et expiration.
  - `diff` — comparaison de deux scans JSON pour détecter les régressions en CI.
  - `report` — rapport de conformité ciblé sur un framework (markdown, pour audit RSSI).
- **Extensible** : ajoutez vos propres règles Rego via `--policy <dir>` et vos
  propres frameworks via `--frameworks-dir`.
- **Binaire autonome** : règles, catalogue tarifaire et référentiels de
  conformité embarqués (`embed.FS`). Aucune dépendance runtime hors API
  Outscale pour le scan live.
- **Autocomplétion** : shell bash / zsh / fish / PowerShell.

---

## Architecture

```text
  Terraform/OpenTofu plan.json           API Outscale (scan live)
              │                                    │
              ▼                                    ▼
    ┌──────────────────────────────────────────────────────┐
    │          osc-policy (binaire Go, autonome)           │
    │                                                      │
    │  ┌────────────────────────────────────────────────┐  │
    │  │  Moteur OPA (SDK Go : open-policy-agent/opa)   │  │
    │  │  ├── policies/security/*.rego                  │  │
    │  │  ├── policies/finops/*.rego                    │  │
    │  │  ├── policies/compliance/*.rego                │  │
    │  │  ├── catalog/prices.yaml (injecté en data)     │  │
    │  │  └── catalog/frameworks/*.yaml (référentiels)  │  │
    │  └────────────────────────────────────────────────┘  │
    │                       │                              │
    │          ┌────────────┴────────────┐                 │
    │          ▼                         ▼                 │
    │  report.Finding[]            report.ScanScore        │
    │          │                         │                 │
    │          └────────────┬────────────┘                 │
    │                       ▼                              │
    │      terminal │ json │ sarif │ junit │ markdown      │
    └──────────────────────────────────────────────────────┘
```

**Principes clés** :

1. Chaque règle `deny contains msg` retourne un **JSON marshalé** contenant
   toutes les métadonnées (`rule_id`, `severity`, `resource_id`, `message`, …).
   Le moteur Go `unmarshal` ce JSON pour construire la struct `Finding`.
2. Les policies embarquées sont chargées via `//go:embed`. Le flag `--policy`
   permet d'ajouter des policies *surchargeables* à côté.
3. Les erreurs d'un collector individuel (ex: pas de droit API OOS) sont
   loggées en warning mais n'interrompent pas le scan.

---

## Installation

### Via mise — backend `ubi` (recommandé, dès qu'une release existe)

[mise](https://mise.jdx.dev/) télécharge le binaire pré-compilé depuis les
GitHub Releases via [Universal Binary Installer](https://github.com/houseabsolute/ubi).
Pas de Go requis côté utilisateur.

```bash
# Dernière release
mise use --global ubi:outscale-srt20/osc-policy

# Version épinglée (recommandé en CI)
mise use --global ubi:outscale-srt20/osc-policy@v1.2.0

# Vérifier
osc-policy version
```

> Les releases sont produites automatiquement par [GoReleaser](.goreleaser.yml)
> via [`.github/workflows/release.yml`](.github/workflows/release.yml) à chaque
> push de tag `v*`. Binaires multi-arch (linux/darwin/windows × amd64/arm64),
> SBOM et checksums inclus pour audit supply chain.

### Via mise — backend `go` (si pas de release disponible)

```bash
# Pré-requis : Go installé (mise peut s'en charger)
mise use --global go@latest

mise use --global go:github.com/outscale-srt20/osc-policy@latest
```

### Depuis les sources (Go ≥ 1.24)

```bash
git clone https://github.com/outscale-srt20/osc-policy.git
cd osc-policy
make build              # binaire ./osc-policy
./osc-policy version
```

### Docker

```bash
docker run --rm -v "$PWD":/work -w /work \
  ghcr.io/outscale-srt20/osc-policy:latest scan plan plan.json
```

---

## Configuration

### Fichier `.osc-policy.yaml`

`osc-policy` cherche un fichier `.osc-policy.yaml` dans le répertoire courant,
puis `~/.osc-policy.yaml`. Le flag `--config <path>` force un chemin.
Utilisez `osc-policy init` pour générer ce fichier interactivement.

```yaml
outscale:
  region: eu-west-2

scan:
  profile: all            # security | finops | compliance | all
  min_severity: LOW       # INFO | LOW | MEDIUM | HIGH | CRITICAL
  fail_on: HIGH           # seuil de code retour non-zéro (par sévérité)
  min_grade: ""           # grade minimal requis A-G ; vide = désactivé
  output: terminal        # terminal | json | sarif | junit | markdown
  skip_rules: []          # ex: [OSC-TAG-001]

policies:
  extra_dir: ""           # policies additionnelles

finops:
  monthly_budget: 0
  cost_estimation: true
  prices_file: ""         # surcharger catalog/prices.yaml

docs:
  output_dir: ./docs/rules
  lang: fr
```

Un exemple complet est disponible dans [`.osc-policy.example.yaml`](.osc-policy.example.yaml).

### Authentification Outscale (scan live)

`osc-policy scan live` utilise le format standard `~/.osc/config.json`
(compatible `osc-cli`) :

```json
{
  "default": {
    "access_key": "ABCDEFGHIJKLMNOPQRST",
    "secret_key": "abcdefghijklmnopqrstuvwxyz0123456789ABCD",
    "host": "outscale.com",
    "region": "eu-west-2"
  },
  "prod": { "access_key": "...", "secret_key": "...", "host": "outscale.com", "region": "eu-west-2" }
}
```

Variables d'environnement reconnues :

| Variable | Rôle |
| -------- | ---- |
| `OUTSCALE_ACCESSKEYID` | Access key |
| `OUTSCALE_SECRETKEYID` | Secret key |
| `OUTSCALE_REGION` | Région par défaut |
| `OSC_CONFIG_FILE` | Chemin alternatif vers `config.json` |

---

## Utilisation de la CLI

### Flags globaux

```text
--config <path>         Fichier de configuration
-o, --output <fmt>      terminal | json | sarif | junit | markdown
--severity <sev>        Sévérité minimale reportée (défaut: LOW)
--profile <p>           security | finops | compliance | all (défaut: all)
--policy <dir>          Répertoire de policies additionnelles
--skip-rule <ids>       IDs à ignorer (répétable, ou CSV)
--tag-filter <k=v>      Filtrer par tag (scan live)
--no-color              Désactiver les couleurs
-q, --quiet             Afficher seulement les findings
--fail-on <sev>         Seuil de code retour non-zéro par sévérité (défaut: HIGH)
--min-grade <A-G>       Exit non-zéro si grade < seuil (combiné par OU avec --fail-on)
--debug                 Mode debug OPA (traces)
```

### `osc-policy scan plan`

Analyse un plan Terraform JSON **avant** déploiement.

```bash
# Générer le plan JSON
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan > plan.json

# Scanner
osc-policy scan plan plan.json

# Filtrer / cibler
osc-policy scan plan plan.json --profile security --severity HIGH
osc-policy scan plan plan.json --skip-rule OSC-VM-005,OSC-TAG-001
osc-policy scan plan plan.json --changes-only    # ignore les ressources no-op
osc-policy scan plan plan.json --output sarif > gl-sast-report.json
```

### `osc-policy scan live`

Analyse les ressources existantes via l'API Outscale.

```bash
osc-policy scan live                                 # profil default
osc-policy scan live --profile-name prod             # profil explicite
osc-policy scan live --profile-name all              # tous les profils (opt-in)
osc-policy scan live --collectors vms,volumes,sgs    # sélectionner les collectors
osc-policy scan live --region eu-west-2
```

Snapshots et drift detection :

```bash
# Capture pour audit offline
osc-policy scan live --snapshot-output snapshot-$(date +%Y%m%d).json

# Rejouer sans API
osc-policy scan live --snapshot-input snapshot-20260101.json

# Drift vs la semaine dernière
osc-policy scan live --compare snapshot-last-week.json
```

Collectors disponibles : `vms`, `volumes`, `sgs`, `ips`, `lbus`, `nets`, `vpn`,
`nics`, `snapshots`, `images`, `keys`, `access`, `oos`, `oks`, `account`, `eim`, `all`.

### `osc-policy scan all`

Lance `scan plan` **et** `scan live`, puis déduplique les findings portant sur
la même ressource.

```bash
osc-policy scan all plan.json --profile-name default
```

### `osc-policy explain`

Affiche la documentation complète d'une règle : description, sévérité, exemples
non-conforme et conforme, étapes de remédiation, frameworks de conformité couverts.

```bash
osc-policy explain OSC-SG-001
osc-policy explain OSC-OKS-003
```

Exemple de sortie :

```text
OSC-SG-001 — SSH (port 22) ouvert à Internet                [HIGH]
────────────────────────────────────────────────────────────────────
Description
  Une règle de security group autorise le port 22 depuis 0.0.0.0/0
  ou ::/0, exposant le service SSH à l'ensemble d'Internet.

Remédiation
  1. Restreindre ip_range à votre CIDR d'administration (ex. 10.0.0.0/8)
  2. Ou utiliser un bastion dédié et supprimer l'accès SSH direct

Non-conforme                          Conforme
  resource "outscale_sg_rule" ...       resource "outscale_sg_rule" ...
    ip_range = "0.0.0.0/0"               ip_range = "10.0.0.0/8"

Frameworks
  ANSSI-BP-028 : R65, R67
  SecNumCloud 3.2 : 13.2, 13.3
  CIS Controls v8 : 4.4, 12.2
  ISO 27001:2022 : A.8.20, A.8.22
```

### `osc-policy init`

Wizard interactif qui génère un fichier `.osc-policy.yaml` dans le répertoire
courant en posant quelques questions sur le profil, la sévérité, le framework
de conformité ciblé, etc.

```bash
osc-policy init                  # interactif
osc-policy init --force          # écraser un fichier existant
```

Le fichier généré peut être versionné en Git pour partager la configuration
avec l'équipe.

### `osc-policy fix`

Génère un **patch Terraform** ou une **commande oapi-cli** pour corriger un
finding. Ne s'applique **jamais** automatiquement — affiche uniquement le code
à valider en MR puis appliquer manuellement.

```bash
osc-policy fix --rule OSC-SG-001 --resource sg-12345678
osc-policy fix --rule OSC-OKS-001 --resource pentest-fresh
```

Si aucun template de remédiation automatique n'existe pour la règle, la commande
renvoie vers `osc-policy explain <rule-id>` pour la remédiation textuelle.

### `osc-policy suppress`

Ajoute une **suppression documentée** au fichier `.osc-policy-ignore`. Chaque
suppression nécessite une raison et peut avoir une date d'expiration.

```bash
# Supprimer un finding pour une ressource donnée
osc-policy suppress \
  --rule OSC-SG-001 \
  --resource sg-12345678 \
  --reason "Bastion temporaire validé par RSSI — ticket #42" \
  --expires 2026-12-31

# Lister les suppressions actives
osc-policy suppress --list
```

Le fichier `.osc-policy-ignore` doit être versionné en Git pour audit. Les
suppressions expirent automatiquement à la date indiquée.

### `osc-policy diff`

Compare deux rapports JSON (`osc-policy scan --output json`) et identifie les
findings **nouveaux** (régressions), **résolus** (progrès) et **inchangés**.

```bash
# Comparer le scan de main avec le scan de la MR
osc-policy diff scan-main.json scan-mr.json

# Bloquer la CI si de nouveaux findings apparaissent
osc-policy diff scan-main.json scan-mr.json --fail-on-new

# Sortie JSON pour post-traitement
osc-policy diff scan-main.json scan-mr.json --output json
```

Cas d'usage typique en CI : capturer le scan de `main` lors du merge, le
stocker en artifact, puis comparer lors de la prochaine MR.

### `osc-policy report`

Génère un **rapport de conformité markdown** ciblé sur un framework de référence,
avec pour chaque contrôle : les règles qui le couvrent et le statut
PASSED / FAILED / NOT_ASSESSED (si un scan JSON est fourni).

```bash
# Rapport sur SecNumCloud 3.2 (sans scan — coverage uniquement)
osc-policy report --framework secnumcloud_3_2

# Rapport ANSSI avec résultats d'un scan live
osc-policy report --framework anssi_bp_028 --scan scan.json

# Export vers fichier
osc-policy report --framework iso_27001_2022 --scan scan.json \
  --output-file audit-iso27001-$(date +%Y%m).md
```

Frameworks disponibles : `anssi_bp_028`, `secnumcloud_3_2`, `cis_controls_v8`,
`iso_27001_2022`, `iso_27017`.

### `osc-policy rules list`

Liste toutes les règles avec leurs métadonnées.

```bash
osc-policy rules list
osc-policy rules list --profile security
osc-policy rules list --severity CRITICAL
osc-policy rules list --output markdown > RULES.md
```

Exemple :

```text
ID            SEVERITY   CATEGORY     TITLE
OSC-SG-001    HIGH       security     SSH (port 22) ouvert à Internet
OSC-SG-002    CRITICAL   security     All-traffic inbound (-1)
OSC-VM-001    CRITICAL   security     VM sans security group
OSC-VM-002    HIGH       security     VM hors subnet (pas dans un Net)
...
```

### `osc-policy rules test`

Exécute `opa test` sur toutes les policies et valide la cohérence des mappings
de conformité (codes référencés vs catalogue embarqué).

```bash
osc-policy rules test
osc-policy rules test --verbose --coverage
```

### `osc-policy docs generate`

Génère la documentation des règles à partir des blocs `# METADATA` des
fichiers `.rego`.

```bash
osc-policy docs generate
osc-policy docs generate --output-dir ./docs/rules --lang fr
```

Génère un fichier markdown par règle dans `output-dir`, incluant description,
sévérité, exemples, remédiations et mappings de conformité.

### `osc-policy completion`

Génère le script d'autocomplétion pour le shell passé en argument :

```bash
osc-policy completion bash        # écrit le script sur stdout
osc-policy completion zsh
osc-policy completion fish
osc-policy completion powershell
```

L'autocomplétion couvre :

- les **valeurs énumérées** (sévérités, profils, formats, collectors)
- les **IDs de règles** (`--skip-rule`)
- les **profils OSC** du fichier `~/.osc/config.json` (`--profile-name`)
- les **fichiers** `.json` pour les plans et snapshots

#### Mise en place persistante

> **Pré-requis** : `osc-policy` doit être résolvable par le shell. Si vous
> utilisez le binaire de développement (`./osc-policy`), remplacez `osc-policy`
> par le chemin absolu dans les commandes ci-dessous.

**Bash** — pré-requis : paquet `bash-completion` installé.

```bash
# Installation system-wide (Linux Debian/Ubuntu/Fedora/Arch)
osc-policy completion bash | sudo tee /etc/bash_completion.d/osc-policy > /dev/null

# Installation user-only
mkdir -p ~/.local/share/bash-completion/completions
osc-policy completion bash > ~/.local/share/bash-completion/completions/osc-policy

# macOS (avec Homebrew)
osc-policy completion bash > "$(brew --prefix)/etc/bash_completion.d/osc-policy"
```

Rechargez le shell (`exec bash`) ou ouvrez un nouveau terminal.

**Zsh** — pré-requis : `compinit` activé dans `~/.zshrc`.

```bash
# Dans le premier répertoire de $fpath
osc-policy completion zsh > "${fpath[1]}/_osc-policy"

# Alternative : emplacement user dédié
mkdir -p ~/.zsh/completions
osc-policy completion zsh > ~/.zsh/completions/_osc-policy
# puis dans ~/.zshrc, avant compinit :
#   fpath=(~/.zsh/completions $fpath)

# Oh My Zsh
osc-policy completion zsh > ~/.oh-my-zsh/completions/_osc-policy
```

**Fish** :

```bash
osc-policy completion fish > ~/.config/fish/completions/osc-policy.fish
```

**PowerShell** :

```powershell
# Persistant — ajoutez à $PROFILE
osc-policy completion powershell >> $PROFILE
```

#### Activation pour la session courante

```bash
source <(osc-policy completion bash)     # Bash
source <(osc-policy completion zsh)      # Zsh
osc-policy completion fish | source      # Fish
```

---

## Formats de sortie

| Format | Usage type |
| ------ | ---------- |
| `terminal` | Lecture humaine, développement local, pipelines interactives |
| `json` | Post-traitement scripté, intégrations internes, `osc-policy diff` |
| `sarif` | GitLab Security Dashboard, GitHub code-scanning |
| `junit` | Vues tests Jenkins / GitLab |
| `markdown` | Commentaires PR, rapports périodiques, wikis |

Tous les formats incluent le bloc de scoring (score global + par service).

---

## Scoring A–G

Le score part de **100** puis applique des pénalités additives par finding
`FAILED` :

| Sévérité | Pénalité |
| -------- | -------: |
| CRITICAL |      −30 |
| HIGH     |      −10 |
| MEDIUM   |       −3 |
| LOW      |       −1 |

**Plafond CRITICAL** : dès qu'un CRITICAL est présent, le score est plafonné
à **45** (grade E au mieux). Un bucket public ne se compense pas.

| Score  | Grade | Libellé      |
| -----: | :---: | ------------ |
| 91–100 | **A** | Excellent    |
|  76–90 | **B** | Bon          |
|  61–75 | **C** | Passable     |
|  46–60 | **D** | Insuffisant  |
|  31–45 | **E** | Mauvais      |
|  16–30 | **F** | Très mauvais |
|   0–15 | **G** | Critique     |

Le même calcul est appliqué **par service** (VM, SG, VOL, …) via le préfixe
du rule ID. Le score global et les scores par service sont exposés dans tous
les formats (JSON, Markdown, SARIF `run.properties.osc_policy_score`).

### Seuil de grade (`--min-grade`)

Complément au `--fail-on` (qui se base sur la sévérité) : déclenche un exit
non-zéro si le grade calculé est **pire** que le seuil demandé.

```bash
osc-policy scan plan plan.json --min-grade B   # échec si grade C, D, E, F ou G
```

Les deux flags sont combinés par **OU** logique : un scan échoue si au moins
un finding dépasse `--fail-on` OU si le grade est inférieur à `--min-grade`.

---

## Conformité multi-framework

Chaque règle est tagguée avec les contrôles qu'elle couvre dans plusieurs
référentiels de conformité, via un bloc `# compliance:` dans le `# METADATA`
Rego :

```yaml
# compliance:
#   anssi_bp_028: ["R65", "R67"]
#   secnumcloud_3_2: ["13.2", "13.3"]
#   cis_controls_v8: ["4.4", "12.2"]
#   iso_27001_2022: ["A.8.20", "A.8.22"]
#   iso_27017: ["CLD.13.1.4"]
```

### Frameworks embarqués (Tier 1)

| Code | Libellé | Version | Contrôles |
| :--- | :------- | :------ | --------: |
| `anssi_bp_028` | ANSSI — Guide d'hygiène informatique | 2.0 | 15 |
| `secnumcloud_3_2` | SecNumCloud — Prestataires de services cloud | 3.2 | 16 |
| `cis_controls_v8` | CIS Critical Security Controls | v8 | 23 |
| `iso_27001_2022` | ISO/IEC 27001:2022 — Annexe A | 2022 | 21 |
| `iso_27017` | ISO/IEC 27017 — Cloud services | 2015 | 7 |

Le contenu des référentiels est embarqué dans le binaire
(`catalog/frameworks/*.yaml`). Pour ajouter vos propres catalogues (ex: une
référence interne ou le futur EUCS), utilisez `--frameworks-dir <dir>` :
les fichiers YAML additionnels suivent le même schéma que les embarqués.

### Rapport de conformité

```bash
# Voir la couverture d'un framework
osc-policy report --framework secnumcloud_3_2

# Rapport avec résultats réels
osc-policy report --framework anssi_bp_028 --scan scan.json --output-file audit.md
```

### Validation des mappings

La commande `osc-policy rules test` vérifie que chaque code
`compliance.<framework>.<control>` référencé par une règle existe bien dans
le catalogue correspondant. Exit 2 en cas de référence invalide.

---

## Codes de sortie

| Code | Signification                                                            |
| ---: | ------------------------------------------------------------------------ |
| `0`  | Aucun finding au-dessus du seuil et grade ≥ `--min-grade`                |
| `1`  | Finding ≥ `--fail-on` OU grade < `--min-grade`                           |
| `2`  | Erreur d'exécution (plan invalide, API inaccessible, config invalide, …) |

---

## Extensibilité (policies custom)

Ajoutez un répertoire de policies externes avec `--policy` :

```bash
osc-policy scan plan plan.json --policy ./my-policies
```

Squelette d'une règle custom :

```rego
# METADATA
# id: OSC-VM-042
# title: Titre actionnable
# description: |
#   Explication concise du problème.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_vm
# source: plan,live
# remediation: |
#   1. Étape 1
#   2. Étape 2
# noncompliant_example: |
#   resource "outscale_vm" "bad" { ... }
# compliant_example: |
#   resource "outscale_vm" "good" { ... }
package security.outscale.vm_042

import rego.v1
import data.lib.modules

deny contains msg if {
    some resource in modules.all_resources
    resource.type == "outscale_vm"
    # condition …
    msg := json.marshal({
        "rule_id":          "OSC-VM-042",
        "severity":         "HIGH",
        "category":         "security",
        "resource_id":      resource.address,
        "resource_type":    resource.type,
        "resource_address": resource.address,
        "message":          "Contexte du finding",
    })
}
```

Les tests se placent dans `<fichier>_test.rego` à côté du fichier source et
sont exécutés par `osc-policy rules test`.

---

## Intégration CI/CD

Des templates prêts à l'emploi sont disponibles dans [`integrations/`](integrations/) :

| Fichier | Cible | Usage |
| --- | --- | --- |
| [`gitlab-ci.yml`](integrations/gitlab-ci.yml) | GitLab CI | Scan plan + report SARIF/JUnit + scan live nightly |
| [`github-actions.yml`](integrations/github-actions.yml) | GitHub Actions | Équivalent GitLab côté GitHub |
| [`gitlab-mr-comment.sh`](integrations/gitlab-mr-comment.sh) | GitLab CI | Commente les findings dans la MR |
| [`slack-webhook.sh`](integrations/slack-webhook.sh) | Slack | Résumé du scan vers un webhook Slack |
| [`crontab-weekly-live.sh`](integrations/crontab-weekly-live.sh) | cron | Scan live hebdomadaire avec rapport HTML archivé |

### GitLab CI (snippet)

```yaml
osc-policy:
  stage: validate
  image: ghcr.io/outscale-srt20/osc-policy:latest
  script:
    - terraform init -backend=false
    - terraform plan -out=plan.tfplan
    - terraform show -json plan.tfplan > plan.json
    - osc-policy scan plan plan.json --output sarif > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths: [gl-sast-report.json]
    when: always
```

### GitHub Actions (snippet)

```yaml
- name: osc-policy scan
  run: osc-policy scan plan plan.json --output sarif > osc-policy.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: osc-policy.sarif
```

### Pre-commit

```yaml
- repo: local
  hooks:
    - id: osc-policy
      name: osc-policy scan plan
      entry: bash -c 'terraform show -json plan.tfplan > plan.json && osc-policy scan plan plan.json'
      language: system
      pass_filenames: false
```

### Pattern recommandé (CI complète)

```text
[ MR ouverte ]
       │
       ├─► CI : terraform plan → plan.json
       │       osc-policy scan plan → SARIF (Code Quality)
       │                            → JUnit (Tests tab)
       │       osc-policy diff scan-main.json scan-mr.json --fail-on-new
       │
       ├─► Webhook : osc-policy explain + commentaires MR inline
       │
       └─► Si merge : scan live nightly → résumé Slack + HTML archivé OOS
```

---

## Développement

### Pré-requis

- Go ≥ 1.24
- [OPA CLI](https://www.openpolicyagent.org/docs/latest/#running-opa) (optionnel — utile pour `opa test` et `opa eval` manuels)

### Cibles make

```bash
make build          # binaire ./osc-policy
make test           # go test ./...
make lint           # golangci-lint
make docker         # image Docker
make docs           # régénère docs/rules/ via la CLI
```

### Arborescence

```text
osc-policy/
├── cmd/                  # commandes cobra
├── internal/
│   ├── engine/           # wrapper OPA
│   ├── collector/        # scan live (par type de ressource)
│   ├── plan/             # parse plan Terraform
│   ├── catalog/          # prix Outscale
│   ├── report/           # Finding, scoring, formats de sortie
│   ├── docgen/           # génération de la doc depuis les .rego
│   └── config/           # viper config
├── policies/
│   ├── lib/              # helpers Rego partagés
│   ├── security/         # règles sécurité
│   ├── finops/           # règles FinOps
│   └── compliance/       # règles compliance
├── catalog/prices.yaml   # grille tarifaire par défaut
├── catalog/frameworks/   # contrôles de référence (ANSSI, SecNumCloud, CIS, ISO)
├── integrations/         # snippets CI/CD (GitLab, GitHub, Slack, cron)
├── version/
├── main.go
└── Makefile
```

### Ajouter une règle

1. Créer le fichier `policies/<category>/<resource>_NNN.rego` avec le bloc
   `# METADATA` complet.
2. Écrire le test associé `policies/<category>/<resource>_NNN_test.rego`.
3. Lancer `osc-policy rules test`.
4. Mettre à jour le `CHANGELOG.md` sous `[Unreleased]`.

---

## Licence

MIT — voir [LICENSE](LICENSE).
