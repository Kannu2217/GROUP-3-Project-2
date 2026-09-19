AeroDrift

Agentic Cloud Topology & AST Remediation Graph

AeroDrift is a self-healing CloudOps daemon. It watches an AWS account for network-security drift — the classic "an engineer opened port 5432 to 0.0.0.0/0 to debug something and forgot to close it" incident — and fixes it autonomously, in about a second, without waiting on a CI/CD pipeline or a human PR review.

Async boto3 ingestion → NetworkX reachability graph → drift detection
   → Python ast-synthesized fix → sandboxed execution → verified self-heal
   → Rich audit dashboard + SQLite history + PDF incident report

Runs with zero AWS credentials and zero cost out of the box — it seeds a realistic VPC inside moto's in-memory AWS emulator, injects a simulated drift incident, and heals it for real via an actual ec2.revoke_security_group_ingress() call against the mock.

Table of Contents
Why this exists
End-to-end flow
The graph model
Module map
Quick start
Walkthrough with code
Running against real AWS
Tests
Project structure
License
Why this exists

Terraform (or any IaC tool) only detects drift on the next plan. It can't act on it without a human clicking "approve" — and a public database sits exposed for the entire gap in between. AeroDrift closes that gap for one well-scoped, high-confidence incident class by treating "is there a path from the Internet to a database?" as a single, cheap graph query it re-runs continuously.

	Manual / IaC-only	AeroDrift
Detection	Next terraform plan	Every ingestion cycle (~seconds)
Fix	Human writes/approves a PR	AST-synthesized automatically
Execution	CI/CD pipeline run	Sandboxed, immediate
Audit trail	PR history	SQLite + per-incident PDF
End-to-end flow
asyncio.gatherboto3 describe_*
build_from_state
detect_drift
No
Yes
ast.parse →NodeTransformer→ ast.unparse
AST safety audit+ restricted exec
AWS Accountor moto sandbox
CloudStatesnapshot
TopologyGraphNetworkX DiGraph
Internet → DBpath exists?
✔ Clean — log & wait
DriftFindingCRITICAL
GeneratedPython fix
SandboxExecutor
Re-ingest &re-check graph
Rich Dashboard
SQLite History
PDF Incident Report
The autonomous remediation sequence
SQLite History
Sandbox Executor
AST Codegen
TopologyGraph
Ingestion
AWS / moto
SQLite History
Sandbox Executor
AST Codegen
TopologyGraph
Ingestion
AWS / moto
asyncio.gather(describe_*)
CloudState
build_from_state()
has_path(internet, db_node)?
DriftFinding (CRITICAL)
ast.parse -> substitute -> ast.unparse
generated source + function name
AST safety audit
revoke_security_group_ingress()
SUCCESS
re-ingest state
rebuild graph
healed = True, save snapshot
log remediation event
The graph model

Every AWS resource becomes a typed node; every real reachability relationship becomes a directed edge. A -> B means "traffic can flow from A to B."

IGW attached
0.0.0.0/0 route
association
open SG rule
governs
direct policy-bypass0.0.0.0/0 ingress
internet
internet_gateway
route_table
subnet
security_group
instance / database

Two independent edge types create the same CRITICAL finding — a security group opened directly (internet -.-> sg), or a rogue public route added to a private subnet's route table (internet -> igw -> rtb -> subnet -> sg) — mirroring how real CSPM tools flag an open database security group as critical even before full network exploitability.

Module map
Module	Responsibility	Key tech
aerodrift/ingestion	Poll AWS concurrently for VPCs, subnets, route tables, SGs, EC2/RDS instances	boto3 + asyncio.gather
aerodrift/graph	Model the account as a directed reachability graph	networkx
aerodrift/codegen	Synthesize the exact fix as real Python source	ast
aerodrift/remediation	Run the generated fix in a locked-down sandbox	exec()+ast
aerodrift/persistence	Snapshot every topology + remediation event; diff any two points in time	sqlite3
aerodrift/dashboard	Live terminal audit view	rich
aerodrift/reports	Per-incident PDF report	reportlab
aerodrift/daemon.py	Orchestrates the full ingest → detect → fix → verify loop	asyncio
Quick start
bash
git clone <your-repo-url> && cd aerodrift
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

python scripts/run_demo.py                # full autonomous loop
python scripts/run_demo.py --dry-run      # generate & show fixes, don't execute
python scripts/run_demo.py --no-chaos     # just show the clean baseline

Expected output (abridged):

No drift detected — topology matches approved baseline.
Injected drift: 0.0.0.0/0 -> 5432/tcp opened on sg-rds-aurora-isolated-db
CRITICAL | prod-aurora-postgres-01 | blast score 80/100 | Internet -> ...
AST Remediation Engine — remediate_drift_sg_...() synthesized in 1.03ms
Execution Sandbox — SUCCESS  duration=7.79ms
Self-heal verified: prod-aurora-postgres-01 is no longer reachable
Incident report written to incident_reports/incident_sg-....pdf

Cycle completed in 1.13s
Walkthrough with code

1. Ingest state concurrently

python
from aerodrift.ingestion import AWSIngestionPipeline

pipeline = AWSIngestionPipeline(region_name="us-east-1")
state = await pipeline.collect()   # 7 boto3 calls, run concurrently

2. Build the graph & detect drift

python
from aerodrift.graph import TopologyGraph

topo = TopologyGraph().build_from_state(state)
findings = topo.detect_drift(state.security_groups)
# [DriftFinding(resource_name='prod-aurora-postgres-01', severity='CRITICAL', ...)]

3. Synthesize the exact fix

python
from aerodrift.codegen import RemediationCodeGenerator

generated = RemediationCodeGenerator().generate_revoke_ingress(findings[0])
print(generated.source_code)
# def remediate_drift_sg_caaf5dcf5daf356a7(region_name='us-east-1'):
#     security_group_id = 'sg-caaf5dcf5daf356a7'
#     ec2 = boto3.client('ec2', region_name=region_name)
#     ...
#     ec2.revoke_security_group_ingress(GroupId=security_group_id, ...)

4. Execute it safely

python
from aerodrift.remediation import SandboxExecutor

result = SandboxExecutor().run(
    generated.source_code, generated.function_name,
    call_kwargs={"region_name": "us-east-1"},
)
print(result.success, result.duration_ms)   # True 7.79

5. Verify, persist, report

python
from aerodrift.persistence import HistoryStore
from aerodrift.reports import generate_incident_report

healed_topo = TopologyGraph().build_from_state(await pipeline.collect())
healed = not healed_topo.is_internet_reachable(f"instance:{findings[0].resource_id}")

HistoryStore().save_snapshot(healed_topo, label="post-heal")
generate_incident_report(findings[0], generated, result, healed)

All five steps above are exactly what AeroDriftDaemon.run_one_cycle() in aerodrift/daemon.py does in one call.

Running against real AWS

Nothing in aerodrift/ depends on moto except daemon.py's mock_aws() context manager and the sandbox seeder. To point this at a real account:

Remove the with mock_aws(): wrapper in aerodrift/daemon.py.
Configure standard boto3 credentials (aws configure, an IAM role, or environment variables).
Grant a least-privilege IAM policy: ec2:Describe*, ec2:RevokeSecurityGroupIngress, rds:DescribeDBInstances.
Run with --dry-run first to confirm findings before enabling autonomous execution.
Tests
bash
pip install -r requirements.txt
pytest tests/ -v

12 tests cover topology/reachability logic, AST generation, the sandbox's safety audit, and SQLite persistence — all against moto, no AWS account or network access required. Runs automatically on every push via .github/workflows/ci.yml.

Project structure
aerodrift/
├── aerodrift/
│   ├── config.py               # baseline policy & constants
│   ├── daemon.py               # orchestrates the full loop
│   ├── ingestion/               # boto3 + asyncio state collection
│   ├── graph/                   # NetworkX reachability engine
│   ├── codegen/                 # ast-based fix synthesis
│   ├── remediation/             # sandboxed execution
│   ├── persistence/             # SQLite history & diffing
│   ├── dashboard/                # Rich terminal UI
│   └── reports/                  # PDF incident reports
├── tests/                         # pytest suite (12 tests)
├── scripts/run_demo.py           # one-command demo entrypoint
├── docs/
│   ├── ARCHITECTURE.md
│   ├── AeroDrift_Project_Documentation.docx
│   ├── AeroDrift_Week1-2_Presentation.pptx
│   └── AeroDrift_Week3-4_Presentation.pptx
├── .github/workflows/ci.yml
├── requirements.txt
├── LICENSE
└── README.md

See docs/ARCHITECTURE.md for the full design rationale and trade-offs.
Website Link : https://cloudops-daemon.preview.emergentagent.com/

License

MIT — see LICENSE.
