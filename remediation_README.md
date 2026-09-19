# `aerodrift/remediation/`

**Execution Sandbox** — safely runs the AST-generated remediation code.

## What's here

| File | Purpose |
|---|---|
| `executor.py` | `SandboxExecutor.run()` — audits, then executes, generated Python source in a restricted namespace. |

## Defense-in-depth layers

Running dynamically generated code is inherently risky, so every
degree of freedom `exec()` normally grants is deliberately narrowed:

1. **AST safety audit** (`_audit_ast`) — re-parses the source *before*
   executing a single line. Rejects anything outside a narrow allow-list:
   only `import boto3` / `from botocore.exceptions import ClientError`,
   exactly one top-level function, and no `exec`/`eval`/`compile`/
   `__import__`/`open`/`os.system`-style calls anywhere in the tree.
2. **Restricted builtins** — executes with a minimal, explicit
   `__builtins__` dict (a dozen safe names) instead of the full Python
   builtin namespace.
3. **Single namespace** — globals doubles as locals so the generated
   module's own `import boto3` statement is visible inside the function
   it defines (a real bug hit and fixed during development: using a
   *separate* locals dict for `exec()` makes top-level imports invisible
   to nested function closures).
4. **Hard timeout** — the call runs on a worker thread via
   `concurrent.futures.ThreadPoolExecutor`, so a hung API call can never
   wedge the daemon.
5. **Full capture** — stdout, return value, and any exception are
   captured into an `ExecutionResult` for the audit trail, success or
   failure.

This is a sandbox suitable for a *trusted* generator (AeroDrift's own AST
engine) producing a *narrow* class of remediation functions — not a
general-purpose untrusted-code sandbox.

## Usage

```python
from aerodrift.remediation import SandboxExecutor

executor = SandboxExecutor(timeout_seconds=10.0)
result = executor.run(
    generated.source_code,
    generated.function_name,
    call_kwargs={"region_name": "us-east-1"},
    dry_run=False,   # True: generate & log the call without executing it
)

print(result.success, result.duration_ms, result.stdout)
```

## Tests

Covered in `tests/test_codegen.py` — the sandbox executes a real fix
against a `moto`-mocked AWS API (and verifies the rule is actually gone
afterward), blocks disallowed imports, and never calls AWS in `dry_run`
mode.
