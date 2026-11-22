# Artifact Profile

- Path: `C:\Users\nafee\AppData\Local\Temp\jre-skill-demo\commons-lang3-3.17.0.jar`
- Size: 673587 bytes
- SHA-256: `6ee731df5c8e5a2976a1ca023b6bb320ea8d3539fbe64c8a1d5cb765127c33b4`
- Generated: 2026-11-22T21:27:54.742132+00:00

## Container

- Type: zip
- Entries: 426
- Class files: 396
- Nested archives: 0
- Multi-release: True
- Signed entries: 0
- Native libraries: 0

## Classes

- Parsed/valid: 396/396
- Major versions: {52: 395, 53: 1}
- With debug attrs: 318
- With SourceFile: 395
- With BootstrapMethods: 93

## Obfuscation indicators (heuristic)

- `reflection-heavy` (medium): {'java/lang/invoke/MethodHandles$Lookup': 189, 'java/lang/reflect/Method.invoke': 5, 'java/net/URLClassLoader': 3, 'java/lang/Class.forName': 3, 'java/lang/reflect/Field.setAccessible': 1} — Reflection can be normal; combined with short names/high-entropy strings it may indicate obfuscation.
- `dynamic-loading-apis` (medium): {'java/lang/invoke/MethodHandles': 283, 'java/lang/ClassLoader': 20, 'java/net/URLClassLoader': 3} — Dynamic loading may indicate plugins, frameworks, or runtime packing; inspect statically before any execution.

## Evidence note

- This report is static, heuristic, and non-executing. Indicators are not proof of maliciousness or specific obfuscator use.
