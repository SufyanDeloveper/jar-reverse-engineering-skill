# Contributing

Thanks for helping improve `jar-reverse-engineering`.

## Core principle

**Do not trade honesty for completeness.** The skill must prefer evidence, traceability, and explicit uncertainty over plausible-looking output.

## Good contributions

- Sanitized real-world recovery case studies
- Improvements to evidence heuristics, triage, or verification checklists
- Better recovery report examples and coverage ledgers
- Clarifications for JVM languages, compiler artifacts, or obfuscation patterns
- Small validation tooling that checks skill structure/quality

## Guidelines

- Keep `SKILL.md` tool-agnostic. Do not hardcode specific decompiler/tool names as the default workflow.
- Do not add brittle facts that go stale easily (e.g., hardcoded version tables) unless they are explicitly marked as examples and verified.
- Preserve the safety model: read-only artifact handling, static-first analysis, no execution of untrusted code by default.
- Any claim added to docs or examples should be evidence-based or clearly labeled as an example/hypothesis.
- Keep changes focused and explain why they improve fidelity, safety, or clarity.

## Before opening a PR

- Ensure `SKILL.md` frontmatter includes `name` and `description`.
- Ensure the folder name matches `name`.
- Ensure references mentioned in `SKILL.md` exist.
- Keep examples sanitized; never include secrets, proprietary artifacts, or private data.
