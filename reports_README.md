# `aerodrift/reports/`

**Incident Reporting** — one PDF per remediation event, suitable for
attaching to a change-management ticket or postmortem.

## What's here

| File | Purpose |
|---|---|
| `incident_report.py` | `generate_incident_report()` — lays out a five-section PDF via ReportLab's `platypus` engine. |

## Report sections

1. **Drift Detected** — resource, resource ID, security group, offending
   rule, and the full attack path NetworkX traced.
2. **How It Was Found** — a short explanation of the reachability query.
3. **AST-Synthesized Remediation** — the exact generated function,
   printed in full (line-wrapped to fit the page).
4. **Execution Result** — status, duration, dry-run flag, captured error.
5. **Self-Heal Verification** — whether the resource is confirmed no
   longer Internet-reachable after the fix.

## Usage

```python
from aerodrift.reports import generate_incident_report

path = generate_incident_report(
    finding=finding,            # DriftFinding
    generated=generated,        # GeneratedRemediation
    execution=result,           # ExecutionResult
    healed=True,
    output_dir="incident_reports",
)
print(f"Report written to {path}")
```

Reports are named `incident_<security_group_id>_<timestamp>.pdf` and
written to `incident_reports/` by default (git-ignored — see the root
`.gitignore`).

## Dependencies

Uses `reportlab` (`pip install reportlab`, already in `requirements.txt`).
No test file of its own; its inputs are covered by `tests/test_codegen.py`
and `tests/test_topology.py`.
