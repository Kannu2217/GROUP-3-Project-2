# AeroDrift — Architecture

## 1. Problem framing

Terraform (or any IaC tool) can only tell you that drift happened the next
time someone runs `plan`. Between the moment an engineer fat-fingers a
security-group rule and the moment a human reviews and applies the fix,
the resource is exposed. AeroDrift removes the human from that specific,
narrow, high-confidence loop: *"a database just became reachable from the
public internet — revoke the exact rule that did it."*

## 2. High-level data flow

```
 ┌───────────────┐      asyncio.gather        ┌───────────────────┐
 │   AWS (or a   │ ───────────────────────▶   │  CloudState        │
 │  moto sandbox)│  boto3 describe_* calls     │  (dataclass)       │
 └───────────────┘                             └─────────┬─────────┘
                                                            │ build_from_state()
                                                            ▼
                                                 ┌────────────────────┐
                                                 │  TopologyGraph      │
                                                 │  (networkx.DiGraph) │
                                                 └─────────┬──────────┘
                                                            │ detect_drift()
                                                            ▼
                                                 ┌────────────────────┐
                                                 │  DriftFinding[]     │
                                                 └─────────┬──────────┘
                                                            │ generate_revoke_ingress()
                                                            ▼
                                                 ┌────────────────────┐
                                                 │ GeneratedRemediation│
                                                 │ (ast.unparse output)│
                                                 └─────────┬──────────┘
                                                            │ SandboxExecutor.run()
                                                            ▼
                                                 ┌────────────────────┐
                                                 │  ExecutionResult    │
                                                 └─────────┬──────────┘
                                    re-ingest & re-check    │
                                    reachability            ▼
                                                 ┌────────────────────┐
                                                 │ Healed? Y/N          │
                                                 └─────────┬──────────┘
                                                            │
                                       ┌────────────────────┼────────────────────┐
                                       ▼                    ▼                    ▼
                              Rich dashboard        SQLite snapshot     PDF incident report
```

## 3. Module design

### 3.1 Ingestion (`aerodrift/ingestion/`)

`AWSIngestionPipeline.collect()` fires seven boto3 `describe_*` calls
concurrently using `asyncio.gather(*[asyncio.to_thread(fn) for fn in
collectors])`. boto3 itself is synchronous; the concurrency comes from
running each blocking call in its own worker thread rather than paying
each API round-trip serially. On a real AWS account this is the
difference between a ~150 ms poll cycle and one that pays every call's
latency back-to-back.

`sandbox_seed.py` builds a small, realistic, two-tier VPC (public
DMZ + isolated private DB subnet, correct route tables, security groups
following least-privilege — the DB SG only accepts 5432 from the app-tier
SG) entirely through the same boto3 client, so the exact same ingestion
code path is exercised whether the client is talking to `moto` or a real
account. `inject_chaos_drift()` reproduces the project brief's incident:
a direct `0.0.0.0/0` ingress rule appended to the database security group.

### 3.2 Topology Engine (`aerodrift/graph/`)

`TopologyGraph.build_from_state()` turns a `CloudState` into a
`networkx.DiGraph` where a directed edge `A → B` means "traffic can flow
from A to B". Two distinct edge types are what make the "0.0.0.0/0 SG
opened directly" and "rogue public route added to a private subnet"
incidents both detectable with the same graph query:

* **Direct policy-bypass edge** `internet → sg:<id>` — added whenever a
  security group carries an ingress rule whose CIDR is `0.0.0.0/0`,
  independent of routing. This matches how real CSPM tooling treats an
  open database security group as a critical finding on its own.
* **Routed edge chain** `internet → igw → rtb → subnet → sg → instance` —
  only exists end-to-end when the route table has an explicit public
  route *and* the security group allows the traffic. This is what a
  "rogue route table entry" drift creates even if the SG rule itself
  looks unremarkable.

`detect_drift()` walks every database-tagged node and asks
`networkx.has_path(graph, "internet", node)` — a single, cheap query,
independent of how many hundreds of resources the account has. When a
path exists it's traced back to the exact offending `IpPermission` and
returned as a `DriftFinding` (resource, security group, port range,
attack path, a simple blast-radius score).

### 3.3 Code Generator (`aerodrift/codegen/`)

Rather than string-templating Python (fragile — one missing quote and you
have a syntax error at runtime, or worse, an injection point),
`RemediationCodeGenerator`:

1. Parses a generic template once with `ast.parse`.
2. Walks it with an `ast.NodeTransformer` and swaps placeholder
   `ast.Constant` nodes for the finding's real values (security-group id,
   protocol, ports, CIDR).
3. Renames the top-level function to something unique and auditable
   (`remediate_drift_sg_0f3a9c1e`).
4. Calls `ast.fix_missing_locations` then `ast.unparse` to emit real
   Python source text, and re-parses the output as a sanity check.

Because the substitution happens on AST nodes rather than strings, the
output is *guaranteed* syntactically valid — there's no way to generate
an unbalanced brace or a broken f-string.

### 3.4 Execution Sandbox (`aerodrift/remediation/`)

Generated code is never trusted blindly. Before it runs:

* `_audit_ast()` re-parses the source and rejects anything outside a
  narrow allow-list: only `import boto3` / `from botocore.exceptions
  import ClientError`, only one top-level function, no `exec`/`eval`/
  `os.system`/`open`/etc. calls anywhere in the tree.
* It then executes with a **minimal `__builtins__`** (no `open`, no
  general `__import__` usage beyond what the module's own `import`
  statements need) and a **single namespace** used as both globals and
  locals — Python's function-closure semantics mean using a *separate*
  locals dict for `exec()` would make top-level `import boto3` invisible
  inside the generated function, which is a real bug this project hit
  and fixed during development (see `docs/DEVELOPMENT_NOTES.md`-style
  commit history / test `test_sandbox_executes_generated_fix_against_moto`).
* The call itself runs on a worker thread with a hard timeout via
  `concurrent.futures.ThreadPoolExecutor`.

### 3.5 Persistence (`aerodrift/persistence/`)

Every topology build is serialized with `networkx.node_link_data` and
stored as JSON in SQLite (`snapshots` table), alongside every remediation
attempt (`remediation_events` table). `HistoryStore.diff_snapshots(a, b)`
loads two snapshots and returns the edge-level `TopologyGraph.diff()` —
"what changed in the network's shape between these two points in time."

### 3.6 Dashboard (`aerodrift/dashboard/`)

`AuditDashboard` uses `rich.tree.Tree` to render the topology
(internet → gateways → route tables → subnets → security groups →
instances), colouring any node on a live attack path bold red with a
`DRIFTED` tag, `rich.table.Table` for the drift/audit-log views, and
`rich.syntax.Syntax` to pretty-print the AST-generated fix with syntax
highlighting before it runs.

### 3.7 Incident Reports (`aerodrift/reports/`)

`generate_incident_report()` uses `reportlab.platypus` to lay out a
five-section PDF per remediation: what drifted, how the topology engine
found it, the exact synthesized fix (line-wrapped for print), the
execution result, and the verification step that re-ingested state and
confirmed the resource is no longer internet-reachable.

### 3.8 Daemon (`aerodrift/daemon.py`)

`AeroDriftDaemon.run_one_cycle()` is the orchestrator: establish/confirm
the baseline, (in the demo) inject chaos, re-ingest, detect drift, and
for every finding — generate, execute, re-verify, persist, report. It is
the only module that imports `moto`, and only to seed/wrap the local
sandbox; swapping that context manager out is the entire change needed
to point AeroDrift at a real AWS account (see README "Running against a
real AWS account").

## 4. Design decisions & trade-offs

| Decision | Why |
|---|---|
| Model reachability as a graph rather than a flat rule list | Path-finding composes correctly across multiple hops (route table + SG), and scales to "is X reachable from Y" for *any* two resources, not just Internet→DB, with no extra code. |
| Two independent edge types for the same finding | Mirrors how real CSPM tools flag an open DB security group as critical even before full network exploitability, while still modelling true routed reachability for the "rogue route" scenario. |
| AST-based codegen instead of string templates | Guarantees syntactic validity; makes "what exactly will run" auditable and diffable; is the literal, defensible answer to "how did you generate this code" in a review. |
| A narrow, allow-listed sandbox instead of a general one | The generator only ever needs to produce one shape of function (call `revoke_security_group_ingress` with fixed args) — the sandbox is scoped to exactly that, not to running arbitrary untrusted code safely in general. |
| `moto` as the default runtime, not a real AWS account | Zero-cost, zero-credential, deterministic CI; the ingestion/graph/codegen/execution code paths are unchanged if pointed at a real account. |
| SQLite over a hosted database | Zero setup, file-based, trivially inspectable (`sqlite3 aerodrift_history.sqlite3`), sufficient for a single-daemon deployment. |

## 5. Known limitations / future work

* Reachability graph only models EC2 + RDS + basic VPC networking — no
  NAT gateways, VPC peering, Transit Gateway, or PrivateLink edges yet.
* Only one remediation "shape" is implemented
  (`revoke_security_group_ingress`); a production version would add
  route-table and NACL remediation generators behind the same AST
  pipeline.
* The sandbox's AST audit is an allow-list appropriate for a *trusted*
  generator producing a *narrow* class of functions — it is not a
  general-purpose untrusted-code sandbox and should not be treated as one.
* Polling is interval-based in the demo; a production deployment would
  prefer EventBridge / CloudTrail-driven triggers for near-real-time
  reaction instead of fixed-interval polling.
