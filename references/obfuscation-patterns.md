# Obfuscation Patterns & Recovery Playbook

Companion to `SKILL.md`. This file describes common JVM obfuscation/protection patterns, static detection signals, and evidence-safe recovery strategies. Signals are **heuristics**, not proof.

## Guiding rule

Detect → classify → gather evidence → recover what is supported → report boundaries. Never claim a specific obfuscator or original name/logic without evidence.

## 1. Identifier renaming

**Signals**
- Short/generated class/method/field names (`a`, `b`, `Il1`, etc.), inconsistent naming schemes.
- Packages flattened into short segments.
- Debug attributes absent or inconsistent with names.

**Recovery**
- Preserve semantics first; treat names as INFERRED unless verified by debug info, mappings, or strong external metadata.
- Use structural/contextual naming only as hypotheses (call sites, type signatures, API usage, resource keys).
- If a mapping file is supplied/found, verify consistency before trusting.

**Do not**
- Present heuristic names as original identifiers.

## 2. String encryption / encoding

**Signals**
- Many high-entropy/base64-like strings.
- Calls to decryptor helpers, `javax.crypto.*`, `Base64` decoders, custom XOR/shift loops.
- Strings flowing through `invokedynamic` or small static methods returning `String`.

**Recovery**
- Locate decryptor routine and data inputs statically.
- Re-implement decryptor as a pure function in an isolated analysis environment; validate on samples.
- Record decrypted values as recovered evidence only when derivation is reproducible and traceable.
- If decryption depends on runtime environment/keys/unavailable payload, mark UNRECOVERED and document boundary.

**Do not**
- Execute untrusted decryptors in-process. Hard rule 2 applies.

## 3. Control-flow obfuscation / flattening

**Signals**
- Large switch dispatchers, state variables controlling loops, unnatural CFG shape.
- Many opaque predicates (conditions that are always true/false but not obvious).
- Exception-based control flow, excessive try/catch handlers.
- Decompiler output with gotos/unstructured artifacts while bytecode is valid.

**Recovery**
- Use disassembly/CFG view as ground truth.
- Compare outputs from independently implemented recovery engines.
- Simplify incrementally: identify dispatcher, state transitions, dead branches; document each transformation.
- If structure cannot be reliably restored, preserve semantics at lower-level description and mark affected structure INFERRED/UNRECOVERED.

**Do not**
- Replace complex control flow with "cleaner" logic that changes behavior.

## 4. Reflection / indirection obfuscation

**Signals**
- Heavy use of `Class.forName`, `Method.invoke`, `Field.setAccessible`, `MethodHandles.Lookup`.
- String construction feeding reflection targets.
- Dynamic proxy/`invokedynamic` indirection.

**Recovery**
- Resolve targets statically where strings/constants are recoverable.
- Build call graph edges as hypotheses when targets are partially resolved.
- Mark unresolved reflective edges explicitly.

## 5. Resource / class encryption, packing, dynamic loading

**Signals**
- Custom `ClassLoader`, `defineClass`, encrypted entries, native loader stubs.
- Missing expected classes in archive but bootstrap/loader present.
- Framework loader layouts (e.g. Spring Boot loader) mixed with payload.

**Recovery**
- Separate packaging/runtime scaffolding from payload.
- Extract nested/plain payload statically when available.
- For runtime-generated/decrypted payloads, only report statically provable facts; any runtime capture requires Hard rule 2 isolation and explicit justification.

## 6. Reference/method parameter obfuscation

**Signals**
- Indirection through bootstrap methods, constant dynamic, invokedynamic-heavy call sites.
- Extra unused parameters, synthetic wrappers, parameter shuffling patterns.

**Recovery**
- Inspect `BootstrapMethods`, `ConstantDynamic`, method handles, and call sites.
- Restore only when semantics are clear; otherwise keep low-level evidence.

## 7. Kotlin/Scala/Groovy/compiler-generated noise

**Signals**
- `kotlin.Metadata`, Scala signature attributes, Groovy call-site classes.
- Synthetic accessors, `$default`, companion objects, state machines.

**Recovery**
- Distinguish language/compiler artifacts from obfuscation.
- Recover language-aware constructs when evidence supports; declare loss when rendering to Java.

## Detection workflow

1. **Profile artifact**: hashes, structure, versions, metadata, debug attrs, signatures, nested archives.
2. **Collect indicators**: naming, string entropy, reflection, crypto, dynamic loading, CFG complexity, bootstrap methods.
3. **Correlate**: multiple weak indicators may justify a medium-confidence hypothesis; single indicator does not.
4. **Report**: list indicators, evidence locations, confidence, and alternative explanations.

## Evidence ledger fields (recommended)

- `indicator_id`
- `location` (class/method/attribute/resource)
- `evidence` (raw observation)
- `interpretation`
- `confidence` (LOW/MEDIUM/HIGH for hypotheses)
- `alternative_explanations`
- `verification_status`
