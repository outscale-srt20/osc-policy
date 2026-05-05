# Contributing to osc-policy

Merci de l'intérêt pour `osc-policy` ! Ce document décrit comment proposer
des contributions de manière efficace.

## Avant de contribuer

- Lire le [README](README.md) pour comprendre le périmètre.
- Pour une vulnérabilité de sécurité, ne pas ouvrir d'issue publique :
  suivre la procédure dans [SECURITY.md](SECURITY.md).
- Pour une nouvelle règle ou un changement de comportement majeur,
  ouvrir une **discussion** ou une **issue** d'abord pour valider la
  pertinence avant d'investir du temps en code.

## Pré-requis dev

- Go ≥ 1.24
- Make
- Optionnel : `golangci-lint`, `pre-commit`

```bash
git clone https://github.com/outscale-srt20/osc-policy.git
cd osc-policy
make build
make test
```

## Ajouter une nouvelle règle Rego

1. **Créer le fichier** dans `policies/<category>/outscale_<resource>_NNN.rego`
   où `<category>` ∈ {`security`, `finops`, `compliance`}.
2. **Métadonnées METADATA** obligatoires en commentaire `# `.
   Voir une règle existante (ex: `policies/security/outscale_sg_001.rego`)
   comme modèle.
3. **Mapping de conformité** : compléter le bloc `compliance:` avec les
   contrôles applicables (ANSSI-BP-028, SecNumCloud 3.2, CIS Controls v8,
   ISO 27001:2022, ISO 27017). Si un contrôle manque dans le catalogue,
   l'ajouter dans `catalog/frameworks/<framework>.yaml`.
4. **Tests Rego** : créer `policies/<category>/outscale_<resource>_NNN_test.rego`
   avec au minimum un cas qui échoue et un cas qui passe.
5. **Build + test** :

   ```bash
   make build
   ./osc-policy rules test
   ./osc-policy rules list | grep OSC-<RESOURCE>-NNN
   ```

6. **Si la règle nécessite des données qui ne sont pas encore collectées**,
   étendre le collector concerné dans `internal/collector/`. Documenter
   les nouvelles APIs Outscale appelées.

## Convention de commit

Préférer un format inspiré de Conventional Commits :

- `feat(rule): add OSC-XYZ-001 — short title`
- `fix(collector): handle empty bucket policy in OOS collector`
- `docs(readme): update install via mise`
- `chore(deps): bump aws-sdk-go-v2 to v1.30`

## Pull request

- Une PR = un sujet (rule, fix, doc), pas de gros lot.
- Vérifier que les tests passent localement (`make test`).
- Si la PR ajoute une règle, mentionner les frameworks couverts dans la
  description.
- Le CI (GitHub Actions) doit être vert avant merge :
  [`ci.yml`](.github/workflows/ci.yml), [`codeql.yml`](.github/workflows/codeql.yml),
  [`osv-scanner.yml`](.github/workflows/osv-scanner.yml),
  [`trufflehog.yml`](.github/workflows/trufflehog.yml).

## Releases

Les releases sont produites automatiquement par GoReleaser sur push d'un
tag `v*` :

```bash
git tag -a v1.2.0 -m "v1.2.0"
git push origin v1.2.0
```

Cf. [`.github/workflows/release.yml`](.github/workflows/release.yml).

## Code of conduct

Voir [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
