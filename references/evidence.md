# Evidence Playbook — reading the artifact as ground truth

Companion to `SKILL.md`. Use when triaging, resolving ambiguity, or grading names.
Nothing here prescribes a tool; it prescribes what counts as proof.

## 1. Class-file evidence

| Evidence | What it proves | Caveats |
|---|---|---|
| `SourceFile` | Compiler-recorded original file name | Can be stripped or forged |
| `LineNumberTable` | Original line mapping; statement boundaries | Absent without debug info |
| `LocalVariableTable` / `LocalVariableTypeTable` | Original local/parameter names and (generic) types | Authoritative when present and sane; often stripped; can be injected fake |
| `MethodParameters` | Parameter names and flags | Real names only if compiled to retain them |
| `Signature` | Author-level generic declaration | Erasure hides generics everywhere else |
| `InnerClasses`, `EnclosingMethod` | Original nesting, simple names, anonymous/local status | Compiler-numbered anonymous names are "original" in the compiler's sense |
| `NestHost` / `NestMembers` | Nest-based private access (Java 11+) | Explains absent access bridges; do not restore bridges that never existed |
| `Record` | Authoritative record components | Generated accessors/equals/hashCode/toString are not author code |
| `PermittedSubclasses` | Sealed hierarchy | Restore `sealed` / `permits` |
| `BootstrapMethods` | Lambda, concatenation, switch bootstraps | Key to idiom restoration (see `fidelity.md`) |
| Annotations (visible/invisible) | Frameworks, nullability, language metadata | Kotlin/Scala carry their own declaration metadata here |
| `Exceptions` | Declared `throws` | Not catch behavior — read exception tables for that |
| `ConstantValue` | Compile-time constants | Constants are inlined into client classes at their compile time; changing a recovered constant does not retroactively change callers |
| `ACC_SYNTHETIC` / `ACC_BRIDGE` | Compiler-generated members | Never emit as source |
| Minor version `65535` | Preview features were enabled | Recompilation needs a matching JDK in preview mode |
| `module-info.class` | Authoritative module declaration | Recover as `module-info.java` when verified |
| Manifest | Entry points, class-path and compiler/build hints, multi-release flag | Hints are weak evidence — corroborate |

Sanity rule: debug information is evidence, not gospel. Uniform single-letter
"names", collisions, or names inconsistent with call-site semantics suggest
renaming or injection — corroborate before trusting.

## 2. Name provenance ladder

1. **Compiler-recorded names:** local variable tables, parameter names, inner-class
   records, record components, source file — original when sane.
2. **Mapping files** (embedded or supplied): verified metadata only after consistency
   checks against actual structure (do entries match real classes, members,
   descriptors?). An inconsistent mapping is a hypothesis, not proof.
3. **Embedded build metadata** (e.g., `META-INF/maven/**/pom.xml`, `pom.properties`)
   and resources: package roots, artifact coordinates — original artifacts.
4. **Conventions, deobfuscation heuristics, call-site semantics:** INFERRED, always.
5. **Invention:** forbidden.

Shaded/relocated package names are packaging artifacts, not original names.
Original coordinates may be recoverable from metadata remnants; the original
package may be UNRECOVERED — say so.

## 3. Uncertainty investigation checklist

When sources disagree or a result looks wrong, work through:

- **Constant pool:** exact constants, class/member references, bootstrap arguments.
- **Descriptors and access flags:** real signatures, varargs, synthetic, bridge,
  static, final, volatile, transient.
- **Exception tables:** catch/finally shape, suppressed-exception scaffolding.
- **Control flow:** branch targets, stack behavior, loop structure.
- **Invocation targets:** virtual vs interface vs static vs special vs dynamic;
  lambda bodies live in private synthetic methods.
- **Cross-class evidence:** call sites, field reads/writes, overrides, annotation
  values, reflection strings, resource lookups.
- **String/resource decryption:** recover the decoding routine's logic and
  re-implement it as a pure function; do not execute artifact code to get values.

Record each resolution in the evidence ledger:
`claim → artifact location (class, member, attribute) → conclusion`.

## 4. Protection taxonomy and its consequences

| Protection | Static recoverability | Consequence for the project |
|---|---|---|
| Identifier renaming | Structure and logic intact | Names INFERRED unless a verified mapping exists |
| Control-flow obfuscation | Semantics recoverable; decompilers may fail or emit wrong code | Manual control-flow reasoning against disassembly; idioms may be unrecoverable |
| String/resource encryption | Values recoverable via the decoding logic | Re-implement the decoder statically; restored values become evidence |
| Packing / encrypted loading / runtime generation | Payload absent from disk | Declare a static boundary (UNRECOVERED) unless sandboxed capture is justified per Hard rule 2 |
| Shading/relocation | Logic intact under rewritten names | Recover original coordinates from metadata where possible |
| Signed entries | Digests authenticate content | Rebuilding invalidates the original signature — report this; never fake it |

## 5. Triage heuristics

- **First-party vs library:** package roots, embedded build metadata, vendor
  manifests, uniform renaming, code-style boundaries.
- **Fat/executable archives:** separate loader scaffolding from payload; recover the
  payload, restore the loader as a dependency or a documented packaging step.
- **Multi-release archives** (`META-INF/versions/<n>/`): recover each version
  variant, diff them, report the differences — never silently keep only the base.
- **Service descriptors** (`META-INF/services/`): original configuration evidence;
  copy byte-identically and use to verify implementation classes.
- **Native libraries:** declare the boundary; recover JNI declarations and loading
  logic only. Native reverse engineering is a different skill.
- **Runtime-generated classes** (proxies, generated bytecode): no source exists.
  Document the generation mechanism instead of decompiling output into the project.
