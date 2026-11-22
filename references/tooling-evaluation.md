# Tooling & Technique Evaluation

Companion to `SKILL.md`. This file helps agents select and compare JVM reverse-engineering capabilities per artifact. It does **not** prescribe a mandatory toolchain. Verify current maintenance, licensing, and capabilities before use.

## Selection criteria

Evaluate candidates against the artifact profile:

- **Input support:** `.class`, `.jar`, `.war`, `.ear`, multi-release, nested jars, Android dex/apk if relevant.
- **Output quality:** readable Java/Kotlin/bytecode, handling of modern language features, resources.
- **Obfuscation resilience:** renamed identifiers, string encryption, control-flow flattening, reflection indirection.
- **Evidence access:** bytecode/disassembly view, CFG, constant pool, attributes, mapping support.
- **Automation:** CLI/headless mode, scripting/API, reproducible output.
- **Safety:** can run statically/offline/sandboxed; no telemetry or untrusted execution requirements.
- **License & trust:** acceptable license, verifiable source/release, maintained.

## Capability categories

| Category | Purpose | Use when | Evaluation notes |
|---|---|---|---|
| Decompiler | Java/Kotlin-like source recovery | Need readable code | Compare multiple engines; verify against bytecode. |
| Disassembler / bytecode viewer | Ground-truth inspection | Any ambiguity, verification | Must expose attributes, CP, bootstrap methods, exception tables. |
| Bytecode framework/API | Programmatic analysis/transform | Detection, metrics, controlled deobfuscation | Prefer mature libs with good classfile support. |
| Deobfuscator/transformer | Remove/normalize obfuscation patterns | Confirmed pattern with safe transform | Require before/after evidence; never run untrusted code. |
| Graph/CFG tooling | Control-flow understanding | Flattening, complex branching | Export/readable graphs help evidence ledger. |
| Mapping tools | Rename/import/export mappings | Renamed artifacts, interop | Validate mapping against actual descriptors. |
| Diff/comparison tools | Compare decompiler outputs or bytecode | Cross-checks, verification | Normalize noise before judging. |
| Build/dependency analyzers | Recover coordinates and project shape | Reconstructing buildable project | Verify checksums/metadata; don't invent versions. |

## Baseline fallback (always available in many JDK installs)

When specialized tools are unavailable, use JDK built-ins as baseline evidence sources and record their output:

- `jar tf <artifact>` — inventory entries/nesting.
- `javap -v -p -c -s <class>` — disassembly, constant pool, descriptors, flags, attributes.
- `jarsigner -verify -verbose <artifact>` — signature verification status.
- `keytool` / checksums — metadata/signature context as applicable.

These do not replace specialized decompilers/analyzers, but they provide trustworthy ground-truth evidence.

## Example ecosystem (verify current status before use)

These are examples, not endorsements or requirements:

- **Decompilers:** Vineflower, CFR, Procyon, JD-Core/JD-GUI family, JADX (also dex/apk), Fernflower-based engines.
- **Bytecode editors/frameworks:** Recaf, ASM, Byte Buddy, Javassist, SootUp/Soot, Krakatau (disassembly/assembly-oriented).
- **Deobfuscation/analysis:** java-deobfuscator ecosystem, deobfuscation transformers in bytecode editors, custom ASM/Soot passes, YARA-like signature scans (static).
- **Diff/mapping:** Jar diff tools, Mapping-IO/Tiny/Enigma/SRG mapping workflows, normalizing bytecode diff scripts.

## Comparison protocol for decompilers

1. Run at least two independently implemented engines on the same classes.
2. Record tool/version/command/config.
3. Normalize superficial formatting differences.
4. For disagreements, inspect bytecode/disassembly and classify: decompiler bug, unsupported pattern, obfuscation, or ambiguous source form.
5. Keep the most evidence-consistent reading; document unresolved discrepancies.
6. Never promote a decompiler's output to RECOVERED without verification.

## Comparison matrix (recommended)

| Class/Method | Engine A | Engine B | Bytecode check | Verdict | Notes |
|---|---|---|---|---|---|
| `com.a.b.c#d` | readable but suspicious | failed/garbled | dispatcher + state var | RECONSTRUCTED MEDIUM | CFG flattening suspected |

## Automation guidance

- Prefer headless/CLI modes for reproducibility.
- Store raw outputs under `recovery/evidence/tool-outputs/<tool-version>/`.
- Hash tool binaries/configs when possible.
- Separate tool output from human-verified conclusions.
- If a tool executes code/plugins from the artifact or untrusted sources, treat as unsafe by default.

## Red flags when evaluating tools

- Claims "100% recovery" or "original source restored" without evidence.
- Requires executing target artifact as part of normal analysis.
- No versioning/reproducibility.
- Obfuscated/closed binaries with no provenance for sensitive environments.
- Outputs that silently rename or "clean up" code without marking uncertainty.
