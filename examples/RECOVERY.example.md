# Recovery Report (Example / Sanitized)

> This is a sanitized example showing the expected reporting style. It does not describe a real proprietary artifact.

## Goal, scope, and assumptions

- **Goal:** Produce a readable, partially buildable source project from `example-app.jar`.
- **Scope:** First-party package `com.example.app.*`; bundled third-party libraries restored as dependencies.
- **Assumptions:** User is authorized to analyze the artifact. Analysis performed statically; no artifact code executed.

## Artifact profile

- **SHA-256:** `<redacted>`
- **Container:** Fat JAR with `BOOT-INF/classes` and `BOOT-INF/lib`
- **Nested archives:** 12 dependency JARs under `BOOT-INF/lib/`
- **Class-file versions:** Major 61 (Java 17 target), no preview flag
- **Languages:** Java; no Kotlin/Scala metadata detected
- **Protections:** Identifier renaming in `com.example.app.obf.*`; no runtime packing detected
- **Evidence assets:** `SourceFile` present for most classes; `LocalVariableTable` mostly absent; Maven metadata found for 9/12 bundled libraries

## Recovery summary

| Area | Status | Confidence | Verification | Notes |
|---|---|---|---:|---|
| `com.example.app.api.*` | RECOVERED | n/a | 24 members | Logic manually verified against bytecode; signatures/resources matched |
| `com.example.app.service.OrderService` | RECONSTRUCTED | HIGH | 11 members | Two independent recovery outputs agreed; control flow verified against disassembly |
| `com.example.app.obf.a` | RECONSTRUCTED | MEDIUM | 6 members | Semantics restored; original class/member names not recoverable |
| `com.example.app.obf.b#c(int)` | INFERRED | MEDIUM | 1 member | Behavior plausible from call sites; one branch unresolved |
| `com.example.app.license.NativeCheck` | UNRECOVERED | n/a | 0 members | JNI call to bundled native library; static JVM evidence insufficient |

## Dependency provenance

| Dependency | Version | Status | Evidence |
|---|---|---|---|
| `org.slf4j:slf4j-api` | 2.0.13 | RECOVERED | `META-INF/maven/.../pom.properties` + checksum match |
| `com.example:internal-util` | unknown | INFERRED | Package/name hints only; no verifiable coordinates |

## Validation performed

- **Compilation:** Attempted with Java 17 target. 3 errors initially; 2 classified as recovery defects and fixed from bytecode evidence; 1 remains unresolved (mapped to UNRECOVERED JNI boundary).
- **Normalized bytecode comparison:** Performed on 18 selected classes after stripping debug attributes and canonicalizing member order. 16 equivalent after normalization; 2 had documented compiler variance (string concatenation bootstrap shape).
- **Behavioral tests:** Not run. No isolated safe harness was available; artifact code was not executed per Hard rule 2.

## Unrecovered / lost information

- Original identifiers in `com.example.app.obf.*` are lost; no verified mapping file found.
- Local variable names unavailable for most methods because debug attributes are stripped.
- Native license check behavior cannot be recovered from JVM bytecode alone.
- Original build scripts were not present in the artifact; generated build files are RECONSTRUCTED.

## Limitations

- This report does not claim source equivalence for the whole artifact.
- Reconstructed build files may require dependency resolution adjustments where coordinates are INFERRED.
- Any deobfuscated name is a hypothesis unless backed by verified mapping/debug evidence.
