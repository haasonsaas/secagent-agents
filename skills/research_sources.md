# Security Skills Research Sources

The expanded skills in `default_security_skills.yaml` were derived from high-signal public rule/query corpora discovered via GitHub CLI (`gh`):

- CodeQL query repository (official)
  - https://github.com/github/codeql
  - Relevant query roots inspected via `gh api`:
    - `python/ql/src/Security` (CWE directories including 022, 078, 079, 089, 285, 352, 502, 611, 918)
- Semgrep community rules (official)
  - https://github.com/semgrep/semgrep-rules
  - Language/rule trees inspected via `gh api`:
    - `python/`
    - `javascript/`

Sample `gh` commands used:

```bash
gh search repos codeql --limit 8 --json name,owner,description,url
gh search repos semgrep-rules --limit 5 --json name,owner,description,url
gh api "repos/github/codeql/contents/python/ql/src/Security?ref=main" | jq -r '.[].name'
gh api "repos/semgrep/semgrep-rules/contents/python?ref=develop" | jq -r '.[].name'
```
