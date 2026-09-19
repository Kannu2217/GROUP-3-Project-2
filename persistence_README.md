# `aerodrift/persistence/`

**Persistence Layer** — SQLite-backed history of every topology snapshot
and remediation event AeroDrift ever produces.

## What's here

| File | Purpose |
|---|---|
| `history_store.py` | `HistoryStore` — two tables (`snapshots`, `remediation_events`), with save/get/list/diff operations. |

## Schema

```sql
CREATE TABLE snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    label TEXT NOT NULL,
    node_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL,
    graph_json TEXT NOT NULL          -- networkx.node_link_data() output
);

CREATE TABLE remediation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    resource_id TEXT NOT NULL,
    security_group_id TEXT NOT NULL,
    function_name TEXT NOT NULL,
    source_code TEXT NOT NULL,        -- the exact AST-generated fix
    success INTEGER NOT NULL,
    duration_ms REAL NOT NULL,
    detail TEXT
);
```

## Usage

```python
from aerodrift.persistence import HistoryStore

store = HistoryStore("aerodrift_history.sqlite3")

snap_id = store.save_snapshot(topo, label="baseline")
store.log_remediation_event(
    resource_id="i-0123...", security_group_id="sg-0123...",
    function_name="remediate_drift_sg_0123...", source_code=generated.source_code,
    success=True, duration_ms=7.8,
)

# Later: "what changed between these two points in time?"
diff = store.diff_snapshots(snap_id_before, snap_id_after)
print(diff)  # {"added_edges": [...], "removed_edges": [...]}
```

Inspect the file directly at any time with the standard `sqlite3` CLI:

```bash
sqlite3 aerodrift_history.sqlite3 "select label, node_count, edge_count from snapshots;"
```

## Tests

Covered in `tests/test_ingestion.py` — snapshots save and diff correctly,
and remediation events are logged and retrievable.
