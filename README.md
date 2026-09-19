# AeroDrift

**Agentic Cloud Topology & AST Remediation Graph**

AeroDrift is a self-healing CloudOps daemon. It watches an AWS account for
network-security drift — the classic "an engineer opened port 5432 to
`0.0.0.0/0` to debug something and forgot to close it" incident — and fixes
it autonomously, in under a second, without waiting on a CI/CD pipeline or a
human PR review.

```
Async boto3 ingestion → NetworkX reachability graph → drift detection
   → Python `ast`-synthesized fix → sandboxed execution → verified self-heal
   → Rich audit dashboard + SQLite history + PDF incident report
```

## Why this exists

Terraform (and any IaC tool) can *detect* drift on the next `plan`. It
cannot *act* on it without a human clicking "approve" — and a public
database is exposed for the entire gap between the incident and that click.
AeroDrift closes that gap by modelling the cloud as a live graph and
treating "is there a path from the Internet to a database?" as a single,
cheap graph query it can re-run continuously.

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.
In short:

| Module | Responsibility | Key tech |
|---|---|---|
| `aerodrift/ingestion` | Poll AWS concurrently for VPCs, subnets, route tables, security groups, EC2/RDS instances | `boto3` + `asyncio.gather` |
| `aerodrift/graph` | Model the account as a directed reachability graph; answer "internet → database?" | `networkx` |
| `aerodrift/codegen` | Synthesize the *exact* `revoke_security_group_ingress` fix as real Python source | `ast` |
| `aerodrift/remediation` | Run the generated fix in a locked-down sandbox (restricted builtins, import allow-list, AST safety audit, timeout) | `exec()` + `ast` |
| `aerodrift/persistence` | Snapshot every topology + remediation event; diff any two points in time | `sqlite3` |
| `aerodrift/dashboard` | Live terminal audit view: topology tree, drift table, generated code, execution result | `rich` |
| `aerodrift/reports` | Per-incident PDF report (what drifted, how it was found, the fix, verification) | `reportlab` |
| `aerodrift/daemon.py` | Orchestrates the full ingest → detect → fix → verify loop | `asyncio` |

## Running it

The whole pipeline runs **with zero AWS credentials and zero cost** by
default: it seeds a realistic VPC/subnet/security-group/EC2 topology inside
[`moto`](https://github.com/getmoto/moto)'s in-memory AWS emulator, injects
a simulated drift incident, and heals it — for real, via a real
`ec2.revoke_security_group_ingress()` call against the mock.

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

python scripts/run_demo.py                # full autonomous loop
python scripts/run_demo.py --dry-run      # generate & show fixes, don't execute
python scripts/run_demo.py --no-chaos     # just show the clean baseline
```

### Running against a real AWS account

Nothing in `aerodrift/` imports or depends on `moto` except
`daemon.py`'s `mock_aws()` context manager and the sandbox seeder. To point
this at a real account:

1. Remove the `with mock_aws():` wrapper in `aerodrift/daemon.py` (or set
   `AWS_PROFILE`/credentials and skip `seed_sandbox_environment()`).
2. Configure standard boto3 credentials (`aws configure`, an IAM role, or
   environment variables).
3. Grant the daemon's IAM role least-privilege access:
   `ec2:Describe*`, `ec2:RevokeSecurityGroupIngress`, `rds:DescribeDBInstances`.
4. Run it read-only first with `--dry-run` to confirm the drift findings
   against your real topology before enabling autonomous execution.

## Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

12 tests cover the topology/reachability logic, AST code generation, the
sandbox's safety audit, and the SQLite persistence/diff layer — all running
against `moto`, so they need no network access or AWS account.

## Project status

Built as a 4-week CloudOps/infrastructure-automation project. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the module-by-module
design rationale and `docs/AeroDrift_Project_Documentation.docx` for the
full write-up (objectives, week-wise plan, testing, results).

## License

MIT — see [`LICENSE`](LICENSE).
