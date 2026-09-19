# `aerodrift/ingestion/`

**Cloud Ingestion Engine** — pulls live AWS network state concurrently.

## What's here

| File | Purpose |
|---|---|
| `aws_client.py` | `AWSIngestionPipeline` — wraps boto3's synchronous `describe_*` calls so seven of them run concurrently via `asyncio.gather(*[asyncio.to_thread(fn) ...])`. Returns a typed `CloudState` dataclass snapshot (VPCs, subnets, route tables, IGWs, security groups, EC2 instances, RDS instances). |
| `sandbox_seed.py` | `seed_sandbox_environment()` builds a realistic two-tier VPC (public app tier + isolated private DB tier, correct route tables, least-privilege security groups) through real boto3 calls against a `moto` sandbox. `inject_chaos_drift()` reproduces the project's core incident: a `0.0.0.0/0` ingress rule accidentally added to the database security group. |

## Why async, if boto3 is synchronous?

boto3/botocore have no native `async`/`await` support. The standard production
pattern — used here — is to run each blocking call in its own worker thread
via `asyncio.to_thread` and `gather` them:

```python
vpcs, subnets, route_tables, igws, sgs, instances, db_instances = await asyncio.gather(
    asyncio.to_thread(self._describe_vpcs),
    asyncio.to_thread(self._describe_subnets),
    asyncio.to_thread(self._describe_route_tables),
    asyncio.to_thread(self._describe_internet_gateways),
    asyncio.to_thread(self._describe_security_groups),
    asyncio.to_thread(self._describe_instances),
    asyncio.to_thread(self._describe_db_instances),
)
```

This turns a ~900ms serial poll (each API round-trip paid back-to-back) into
one that completes in well under 200ms against a real account.

## Usage

```python
from aerodrift.ingestion import AWSIngestionPipeline, seed_sandbox_environment, inject_chaos_drift
from moto import mock_aws

with mock_aws():
    ids = seed_sandbox_environment()          # build the clean baseline
    inject_chaos_drift(ids.db_sg_id)          # simulate the incident

    pipeline = AWSIngestionPipeline()
    state = await pipeline.collect()          # -> CloudState
```

## Running against real AWS

Nothing in `aws_client.py` depends on `moto`. Point `AWSIngestionPipeline` at
a real boto3 session (standard credentials via `aws configure`, an IAM role,
or environment variables) and it ingests real state unmodified. Only
`sandbox_seed.py` is sandbox-specific — it's used for demos, tests, and CI.

## Tests

Covered in `tests/test_ingestion.py` — verifies all seven collectors return
data concurrently against a `moto`-mocked account.
