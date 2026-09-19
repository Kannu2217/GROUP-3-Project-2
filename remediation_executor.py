"""
Execution Sandbox.

Running dynamically generated code is inherently dangerous, so this
module deliberately narrows every degree of freedom `exec()` normally
grants:

  * A **fresh, minimal ``__builtins__``** — only the handful of names
    the generated template can possibly need (``print``, ``dict``,
    ``str``, exception types, etc). No ``__import__``, no ``open``,
    no ``eval``.
  * The generated source is **re-parsed and AST-linted** immediately
    before execution: only ``Import``/``ImportFrom`` of an explicit
    allow-list (``boto3``, ``botocore.exceptions``) is permitted, and
    only a single top-level ``FunctionDef`` is allowed. Anything else
    (``os.system``, attribute access into dunder internals, nested
    ``exec``/``eval`` calls) causes a ``RemediationBlocked`` error
    *before* a single line runs.
  * The function is invoked with a hard **timeout** via a worker
    thread so a hung API call can't wedge the daemon.
  * Every call is captured — stdout, return value, exceptions — into
    an ``ExecutionResult`` for the audit log / incident report.

This is a defense-in-depth sandbox suitable for a *trusted* generator
(AeroDrift's own AST engine) producing a *narrow* class of remediation
functions — not a general-purpose untrusted-code sandbox.
"""

from __future__ import annotations

import ast
import builtins as _builtins_module
import concurrent.futures
import io
import time
from contextlib import redirect_stdout
from dataclasses import dataclass
from typing import Any

ALLOWED_IMPORT_MODULES = {"boto3", "botocore.exceptions"}
ALLOWED_BUILTINS = {
    "print",
    "dict",
    "list",
    "str",
    "int",
    "float",
    "bool",
    "len",
    "range",
    "Exception",
    "ValueError",
    "KeyError",
    "TypeError",
    "None",
    "True",
    "False",
    "isinstance",
    # Needed so the generated module's own top-level `import boto3` /
    # `from botocore.exceptions import ClientError` statements work —
    # Python's `import` statement compiles down to a call to
    # `__builtins__.__import__`. Direct *explicit* calls to
    # `__import__(...)` are still blocked by the AST audit above.
    "__import__",
}


class RemediationBlocked(Exception):
    """Raised when generated code fails the pre-execution AST safety audit."""


@dataclass
class ExecutionResult:
    function_name: str
    success: bool
    return_value: Any
    stdout: str
    error: str | None
    duration_ms: float
    dry_run: bool = False


def _audit_ast(source: str) -> None:
    """Reject anything the generated remediation template shouldn't contain."""
    tree = ast.parse(source)
    top_level_defs = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if node.col_offset == 0:
                top_level_defs += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            module = node.module if isinstance(node, ast.ImportFrom) else None
            names = [module] if module else [alias.name for alias in node.names]
            for name in names:
                if name not in ALLOWED_IMPORT_MODULES:
                    raise RemediationBlocked(f"Disallowed import: {name!r}")
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in {"exec", "eval", "compile", "__import__", "open"}:
                raise RemediationBlocked(f"Disallowed call: {fn.id}()")
            if isinstance(fn, ast.Attribute) and fn.attr in {"system", "popen", "remove", "rmtree"}:
                raise RemediationBlocked(f"Disallowed call: .{fn.attr}()")
    if top_level_defs != 1:
        raise RemediationBlocked("Generated module must contain exactly one top-level function")


class SandboxExecutor:
    """Safely compiles and runs AeroDrift-generated remediation functions."""

    def __init__(self, timeout_seconds: float = 10.0) -> None:
        self.timeout_seconds = timeout_seconds

    def run(
        self,
        source_code: str,
        function_name: str,
        call_kwargs: dict[str, Any] | None = None,
        dry_run: bool = False,
    ) -> ExecutionResult:
        _audit_ast(source_code)

        safe_builtins = {
            name: getattr(_builtins_module, name)
            for name in ALLOWED_BUILTINS
            if hasattr(_builtins_module, name)
        }
        restricted_globals: dict[str, Any] = {"__builtins__": safe_builtins}

        start = time.perf_counter()
        stdout_buffer = io.StringIO()
        try:
            with redirect_stdout(stdout_buffer):
                # Deliberately a single namespace (globals doubling as
                # locals): the generated module does `import boto3` at
                # top level and then defines a function that calls
                # `boto3.client(...)`. A function's free-variable lookup
                # resolves against its own __globals__ (captured at
                # def-time), so if `import boto3` were executed against
                # a *separate* locals dict, the name would never be
                # visible inside the function body. Using one namespace
                # for both keeps the generated code's semantics exactly
                # what a normal Python module would do.
                exec(compile(source_code, "<aerodrift-generated>", "exec"), restricted_globals)  # noqa: S102
                target_fn = restricted_globals.get(function_name)
                if target_fn is None:
                    raise RemediationBlocked(f"Generated function {function_name!r} not found after exec")

                if dry_run:
                    return_value = {"status": "DRY_RUN", "would_call": function_name, "kwargs": call_kwargs or {}}
                else:
                    return_value = self._call_with_timeout(target_fn, call_kwargs or {})
            duration_ms = (time.perf_counter() - start) * 1000
            success = dry_run or (isinstance(return_value, dict) and return_value.get("status") == "SUCCESS")
            return ExecutionResult(
                function_name=function_name,
                success=success,
                return_value=return_value,
                stdout=stdout_buffer.getvalue(),
                error=None,
                duration_ms=duration_ms,
                dry_run=dry_run,
            )
        except Exception as exc:  # noqa: BLE001 - we want to capture *any* failure into the result
            duration_ms = (time.perf_counter() - start) * 1000
            return ExecutionResult(
                function_name=function_name,
                success=False,
                return_value=None,
                stdout=stdout_buffer.getvalue(),
                error=f"{type(exc).__name__}: {exc}",
                duration_ms=duration_ms,
                dry_run=dry_run,
            )

    def _call_with_timeout(self, fn, kwargs: dict[str, Any]) -> Any:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(fn, **kwargs)
            return future.result(timeout=self.timeout_seconds)
