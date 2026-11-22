# JAR Reverse Engineering Skill

An Agent Skill for recovering and reconstructing source projects from compiled JVM artifacts (`.jar`, `.war`, `.ear`, `.class`) with **evidence-graded fidelity**.

This skill is designed for agents that need to do more than "run a decompiler": it defines a rigorous standard of proof for JVM reverse engineering, source recovery, bytecode analysis, and buildable project reconstruction.

## Why this skill

Most decompilation workflows fail in predictable ways: they trust tool output too much, blur decompiler guesses with original source, ignore compiler artifacts, or silently fill gaps to make code "look complete".

This skill takes the opposite approach:

- **Evidence over output.** Bytecode and class-file structure are ground truth. Decompiler output is a hypothesis until verified.
- **No hardcoded toolchain.** Every artifact is different. The skill tells the agent how to inspect, select, and verify tools per artifact instead of prescribing a brittle stack.
- **Honest uncertainty.** Missing or ambiguous information is labeled, traced, and reported — never fabricated.
- **Compiler-aware recovery.** Lambdas, generics, records, try-with-resources, enums, and other desugared constructs are restored as source-level idioms when evidence supports them.
- **Safety by default.** The original artifact stays read-only; artifact code is not executed unless explicitly justified and isolated.

## What it covers

- JAR / WAR / EAR / CLASS artifact triage
- First-party vs bundled dependency separation
- Java and other JVM languages (Kotlin, Scala, Groovy, mixed artifacts)
- Obfuscation and protection boundaries
- Fat/executable archives and framework layouts (including Spring Boot `BOOT-INF/`), multi-release JARs, nested archives, service descriptors, manifests
- Name provenance and deobfuscation confidence
- Compiler artifact recognition and idiom restoration
- Verification protocol with normalization, coverage ledger, and optional safe evidence-derived tests
- Recovery reporting with traceable evidence and explicit unrecovered/lost information

## Repository structure

```text
jar-reverse-engineering/
├── SKILL.md                  # Core skill: rules, workflow, statuses, deliverables
├── README.md                 # Repository overview and usage
├── CONTRIBUTING.md           # Contribution guidelines
├── LICENSE                   # MIT license
├── .gitignore
├── .github/
│   └── workflows/
│       └── validate.yml      # Basic structure/frontmatter checks
├── examples/
│   └── RECOVERY.example.md   # Sanitized example recovery report
└── references/
    ├── evidence.md           # Class-file evidence, name provenance, protections, triage
    └── fidelity.md           # Desugaring catalog, JVM language notes, verification protocol
```

`SKILL.md` is self-sufficient. The `references/` files provide deeper playbooks that an agent can load on demand.

## Install

### Agent Skills-compatible runtimes

Copy the `jar-reverse-engineering/` folder into your agent's skills directory. The folder name matches the `name` field in `SKILL.md` frontmatter.

### Manual / prompt-based use

If your runtime does not support skill folders, attach `SKILL.md` as the operating instruction for the task. Include `references/evidence.md` and `references/fidelity.md` when the agent can load supporting files.

## How to use

Ask the agent to recover or analyze a JVM artifact, for example:

- "Recover readable Java sources from this JAR and produce a recovery report."
- "Turn this WAR into a buildable source project, but keep third-party libs as dependencies."
- "Analyze this obfuscated JAR and tell me what can be recovered statically."
- "Inspect these class files and explain what is original evidence vs decompiler guesswork."

The skill guides the agent to produce:

```text
recovery/
  original/     # untouched artifact + recorded SHA-256
  evidence/     # disassembly, metadata dumps, cross-check notes, coverage ledger
  project/      # reconstructed sources, resources, build files
  RECOVERY.md   # recovery report
```

## Evidence model

Claims are labeled at the smallest meaningful unit (logic, name, dependency version, class, etc.):

| Status | Meaning | Confidence |
|---|---|---|
| `RECOVERED` | Verified against original bytecode or justified normalized equivalence | n/a |
| `RECONSTRUCTED` | Supported by multiple consistent evidence sources | HIGH / MEDIUM |
| `INFERRED` | Plausible from indirect evidence, unconfirmed | MEDIUM at most |
| `UNRECOVERED` | Cannot be reliably restored from available evidence | n/a |

Compilation success is **not** proof of equivalence. Deobfuscated names are **not** original names unless verified.

## Safety and legal

- Treat artifacts as untrusted. Static analysis is the default.
- Do not execute untrusted bytecode, loaders, decryptors, or build plugins outside an explicitly justified isolated sandbox.
- Preserve the original artifact; keep derived outputs separate.
- Assume the user is authorized to analyze the artifact. Respect licenses and third-party redistribution constraints.

## Design notes

- No tool names are hardcoded; the skill requires per-artifact tool selection and verification.
- No class-file version table is baked in; agents must verify mappings against current references.
- The skill distinguishes author code from compiler-generated/synthetic artifacts.
- Gaps are first-class outputs: unresolved areas must be reported, not hidden.

## Contributing

Contributions are welcome, especially:

- Real-world recovery case studies (sanitized/anonymized)
- Improvements to evidence heuristics and verification checklists
- Better examples of recovery reports and coverage ledgers
- Clarifications for non-Java JVM languages and obfuscation patterns

See [CONTRIBUTING.md](./CONTRIBUTING.md). Keep the core principle: **do not trade honesty for completeness**.

## License

[MIT](./LICENSE)
