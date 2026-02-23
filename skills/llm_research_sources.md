# LLM Security Skills Research Sources

This profile (`llm_security_skills.yaml`) was built from publicly available security taxonomies, benchmarks, and defense catalogs discovered with GitHub CLI.

## Primary references

- OWASP LLM / GenAI risk ecosystem (community repos and derivatives discovered via `gh search`)
- Prompt injection defense catalogs and taxonomies:
  - https://github.com/tldrsec/prompt-injection-defenses
  - https://github.com/Arcanum-Sec/arc_pi_taxonomy
  - https://github.com/protectai/rebuff
- Agent security benchmark projects discovered via `gh search`:
  - https://github.com/agiresearch/ASB
  - https://github.com/facebookresearch/wasp

## Supporting implementation corpora

- CodeQL security query corpus
  - https://github.com/github/codeql
- Semgrep community rule corpus
  - https://github.com/semgrep/semgrep-rules

## Example discovery commands

```bash
gh search repos "OWASP Top 10 LLM" --limit 10 --json name,owner,description,url
gh search repos "prompt injection" --limit 10 --json name,owner,description,url
gh search repos "agent security" --limit 10 --json name,owner,description,url
```

These references were used to shape detector and manager patterns for agentic risks: prompt injection, tool abuse, data exfiltration, identity confusion, unsafe autonomy, RAG poisoning, and cost abuse.
