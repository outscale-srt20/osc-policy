# Intégrations osc-policy

Scripts et templates pour brancher osc-policy à votre pipeline CI/CD et à
vos canaux d'alerte.

## Catalogue

| Fichier | Cible | Usage |
| --- | --- | --- |
| [`gitlab-ci.yml`](gitlab-ci.yml) | GitLab CI | Job qui scanne le plan Terraform et fait échouer la MR sur Critical/High |
| [`gitlab-mr-comment.sh`](gitlab-mr-comment.sh) | GitLab CI | Commente les findings directement dans la MR (notes inline) |
| [`slack-webhook.sh`](slack-webhook.sh) | Slack | Envoie un résumé du scan à un webhook Slack (incident, daily) |
| [`github-actions.yml`](github-actions.yml) | GitHub Actions | Équivalent gitlab-ci.yml côté GitHub |
| [`crontab-weekly-live.sh`](crontab-weekly-live.sh) | cron | Scan live hebdomadaire avec rapport HTML archivé |

## Pattern recommandé

```text
[ MR ouverte ]
       │
       ├─► CI : terraform plan -out=plan.out
       │       terraform show -json plan.out > plan.json
       │       osc-policy scan plan plan.json --output sarif --severity HIGH
       │       → SAST report visible dans la MR
       │       → fail-on=HIGH bloque le merge si CRITICAL/HIGH
       │
       ├─► Webhook GitLab notes : commentaires inline sur la MR
       │
       └─► Si merge : déclencher un scan live nightly
                      → résumé Slack si nouveaux findings
                      → rapport HTML archivé dans OOS
```

## Sortie d'osc-policy compatibles

| Format | Cas d'usage |
| --- | --- |
| `--output sarif` | GitLab/GitHub Code Quality, intégration native |
| `--output junit` | GitLab CI test report (visible dans l'onglet "Tests") |
| `--output json` | Parsing dans scripts custom (jq, post-traitement) |
| `--output markdown` | Rapport humain (PDF, Confluence, README) |
| `--output terminal` | CLI, logs CI |
