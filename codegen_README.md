# `aerodrift/codegen/`

**AST Code Generator** — the metaprogramming heart of AeroDrift. Synthesizes
the exact-fix remediation function as real, syntactically-guaranteed Python
source, using the `ast` module rather than string templating.

## What's here

| File | Purpose |
|---|---|
| `ast_generator.py` | `RemediationCodeGenerator.generate_revoke_ingress()` — parses a generic template, substitutes real values from a `DriftFinding` via an `ast.NodeTransformer`, and emits runnable source via `ast.unparse()`. |

## How it works

1. **Parse once**: a generic remediation template (`import boto3`, a
   `try/except` around `revoke_security_group_ingress`) is parsed with
   `ast.parse()` into a real syntax tree.
2. **Transform**: an `ast.NodeTransformer` walks the tree and swaps
   placeholder `Constant` nodes (`"__SG_ID__"`, `"__FROM_PORT__"`, etc.) for
   the finding's real values — security-group id, protocol, ports, CIDR.
3. **Rename**: the function is renamed uniquely per security group
   (`remediate_drift_sg_0f3a9c1e`) so every generated fix is independently
   traceable in the audit log.
4. **Unparse & verify**: `ast.fix_missing_locations()` then `ast.unparse()`
   emits the final source text — and it is immediately re-parsed with
   `ast.parse()` as a belt-and-braces syntax sanity check.

Because substitution happens on real AST nodes instead of strings, the
output is *guaranteed* syntactically valid — there's no way to generate an
unbalanced brace or a broken f-string the way naive `.format()` /
f-string templating could.

## Usage

```python
from aerodrift.codegen import RemediationCodeGenerator

gen = RemediationCodeGenerator()
generated = gen.generate_revoke_ingress(finding, region_name="us-east-1")

print(generated.function_name)     # remediate_drift_sg_caaf5dcf5daf356a7
print(generated.synthesis_ms)      # ~1ms
print(generated.source_code)       # full, runnable Python source
```

Hand `generated.source_code` and `generated.function_name` to
`aerodrift.remediation.SandboxExecutor.run()` to actually execute it.

## Tests

Covered in `tests/test_codegen.py` — generated source is always valid
Python with no leftover template placeholders, and two findings never
collide on function name.
