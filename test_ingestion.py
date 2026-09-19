"""Tests for the async boto3 ingestion pipeline and the SQLite history store."""

import os

import pytest
from moto import mock_aws

from aerodrift.graph.topology import TopologyGraph
from aerodrift.ingestion.aws_client import AWSIngestionPipeline
from aerodrift.ingestion.sandbox_seed import seed_sandbox_environment
from aerodrift.persistence.history_store import HistoryStore


@pytest.mark.asyncio
async def test_ingestion_pipeline_collects_all_resource_types():
    with mock_aws():
        seed_sandbox_environment()
        pipeline = AWSIngestionPipeline()
        state = await pipeline.collect()

        # moto seeds a default VPC (172.31.0.0/16) with its own default
        # subnets/SGs per region, in addition to everything
        # seed_sandbox_environment() explicitly creates — so assert
        # "at least", not "exactly", except where we fully control it.
        assert len(state.vpcs) >= 1
        subnet_names = {
            tag["Value"]
            for s in state.subnets
            for tag in s.get("Tags", [])
            if tag["Key"] == "Name"
        }
        assert {"Subnet-Public-DMZ-1a", "Subnet-Isolated-DB-1b"} <= subnet_names
        assert len(state.internet_gateways) >= 1
        assert len(state.security_groups) >= 2  # sg-public + sg-db (+ defaults)
        assert len(state.instances) == 2
        assert state.resource_count() > 0


@pytest.mark.asyncio
async def test_history_store_saves_and_diffs_snapshots(tmp_path):
    db_path = str(tmp_path / "test_history.sqlite3")
    store = HistoryStore(db_path=db_path)
    try:
        with mock_aws():
            seed_sandbox_environment()
            pipeline = AWSIngestionPipeline()
            state = await pipeline.collect()
            topo = TopologyGraph().build_from_state(state)

            snap_id_1 = store.save_snapshot(topo, label="baseline")
            snap_id_2 = store.save_snapshot(topo, label="baseline-again")

            snapshots = store.list_snapshots()
            assert len(snapshots) == 2

            diff = store.diff_snapshots(snap_id_1, snap_id_2)
            assert diff["added_edges"] == []
            assert diff["removed_edges"] == []
    finally:
        store.close()
        if os.path.exists(db_path):
            os.remove(db_path)


def test_history_store_logs_remediation_events(tmp_path):
    db_path = str(tmp_path / "test_history2.sqlite3")
    store = HistoryStore(db_path=db_path)
    try:
        store.log_remediation_event(
            resource_id="i-123",
            security_group_id="sg-123",
            function_name="remediate_drift_sg_123",
            source_code="def remediate_drift_sg_123(): pass",
            success=True,
            duration_ms=12.3,
        )
        events = store.list_remediation_events()
        assert len(events) == 1
        assert events[0]["success"] is True
    finally:
        store.close()
        if os.path.exists(db_path):
            os.remove(db_path)
