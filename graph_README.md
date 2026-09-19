# `aerodrift/graph/`

**Topology Engine** — models the AWS account as a directed reachability
graph and answers: *"is there a path from the Internet to a database?"*

## What's here

| File | Purpose |
|---|---|
| `topology.py` | `TopologyGraph` wraps a `networkx.DiGraph`. `build_from_state()` turns an ingested `CloudState` into the graph; `detect_drift()` walks every database node and reports any that are reachable from the Internet, with the full attack path. |

## The graph model

**Nodes** (six types): `internet`, `internet_gateway`, `route_table`,
`subnet`, `security_group`, `instance` (or `database`).

**Edges** — a directed edge `A -> B` means "traffic can flow from A to B":

```
internet    -> igw          always, for every attached Internet Gateway
igw         -> rtb          only if that route table has an explicit
                             0.0.0.0/0 route targeting the IGW
rtb         -> subnet       structural: subnet is associated with that RT
subnet      -> sg           only if the SG governs an instance in that
                             subnet AND has an open (0.0.0.0/0) rule
internet    -> sg           direct "policy bypass" edge — added whenever
                             a security group has an open ingress rule,
                             independent of routing
sg          -> instance     structural: SG governs the instance
```

Two independent ways to create the same finding (a direct SG rule, or a
routed chain through a rogue public route) mirror how real CSPM tooling
treats an open database security group as critical on its own, while
still modelling genuine routed reachability.

## Usage

```python
from aerodrift.graph import TopologyGraph

topo = TopologyGraph().build_from_state(cloud_state)

for db_node in topo.database_nodes():
    if topo.is_internet_reachable(db_node):
        path = topo.find_path("internet", db_node)
        print(" -> ".join(path))

findings = topo.detect_drift(cloud_state.security_groups)
# [DriftFinding(resource_name='prod-aurora-postgres-01', severity='CRITICAL', ...)]
```

## Serialization & diffing

`to_json_dict()` / `from_json_dict()` round-trip the graph through
`networkx.node_link_data` for SQLite storage (see `aerodrift/persistence/`).
`diff(other)` compares two `TopologyGraph` instances and reports exactly
which edges were added or removed — "what changed in the network's shape
between these two snapshots."

## Tests

Covered in `tests/test_topology.py` — baseline has zero findings, injected
drift is detected with the correct attack path, and the graph survives a
JSON round-trip.
