# Real-world static analysis examples

These folders contain **static analysis outputs only** (profiles/scans/reports) generated from publicly available artifacts. The original JAR binaries are **not** redistributed here.

Purpose: demonstrate that the toolkit runs on real artifacts and produces evidence-oriented outputs. These are not full recovery projects and not claims of original source equivalence.

## Included

- `commons-lang3/` — Apache Commons Lang 3.17.0 (Apache-2.0, Maven Central). Analyzed statically with `scripts/artifact_profile.py` and `tools/jvmtool scan`. No artifact code was executed.
