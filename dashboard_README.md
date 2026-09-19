# `aerodrift/dashboard/`

**Audit Dashboard** — a `rich`-powered terminal UI: live topology tree,
drift findings table, syntax-highlighted generated code, and the
remediation audit log.

## What's here

| File | Purpose |
|---|---|
| `cli.py` | `AuditDashboard` — one method per dashboard section. |

## Views

| Method | Renders |
|---|---|
| `banner()` | The AeroDrift title panel. |
| `render_topology_tree(topo, drifted_node_ids)` | The full topology as a `rich.tree.Tree`, walking outward from the `internet` node. Any node on a live attack path is bold red with a `DRIFTED` tag. |
| `render_drift_table(findings)` | A `rich.table.Table` of every `DriftFinding` — severity, resource, security group, offending rule, blast score, attack path. |
| `render_generated_code(generated)` | The AST-synthesized fix, syntax-highlighted via `rich.syntax.Syntax`, with synthesis time and AST node count in the panel title. |
| `render_execution_result(result)` | Success/failure, duration, captured stdout/error from the sandbox. |
| `render_healed_confirmation(name, healed)` | Green confirmation once the graph is rebuilt and the path no longer exists (or a red escalation notice if it doesn't). |
| `render_remediation_log(events)` | The full historical audit log from `HistoryStore`. |

## Usage

```python
from aerodrift.dashboard import AuditDashboard

dash = AuditDashboard()
dash.banner()
dash.render_topology_tree(topo, drifted_node_ids={"instance:i-0123..."})
dash.render_drift_table(findings)
```

This module has no test file of its own — it's exercised end-to-end every
time `scripts/run_demo.py` runs, and its inputs (`DriftFinding`,
`GeneratedRemediation`, `ExecutionResult`) are unit-tested in their
respective modules.
