"""Unit tests for the Topology Engine's reachability / drift logic."""

import pytest
from moto import mock_aws

from aerodrift.graph.topology import TopologyGraph
from aerodrift.ingestion.aws_client import AWSIngestionPipeline
from aerodrift.ingestion.sandbox_seed import inject_chaos_drift, seed_sandbox_environment


@pytest.mark.asyncio
async def test_baseline_topology_has_no_drift():
    with mock_aws():
        seed_sandbox_environment()
        pipeline = AWSIngestionPipeline()
        state = await pipeline.collect()
        topo = TopologyGraph().build_from_state(state)

        findings = topo.detect_drift(state.security_groups)
        assert findings == []

        for db_node in topo.database_nodes():
            assert not topo.is_internet_reachable(db_node)


@pytest.mark.asyncio
async def test_chaos_drift_is_detected_with_correct_attack_path():
    with mock_aws():
        ids = seed_sandbox_environment()
        inject_chaos_drift(ids.db_sg_id, port=5432)

        pipeline = AWSIngestionPipeline()
        state = await pipeline.collect()
        topo = TopologyGraph().build_from_state(state)

        findings = topo.detect_drift(state.security_groups)
        assert len(findings) == 1

        finding = findings[0]
        assert finding.security_group_id == ids.db_sg_id
        assert finding.from_port == 5432
        assert finding.to_port == 5432
        assert finding.cidr == "0.0.0.0/0"
        assert finding.severity == "CRITICAL"
        assert finding.attack_path[0] == "Internet (0.0.0.0/0)"
        assert finding.attack_path[-1] != finding.attack_path[0]


@pytest.mark.asyncio
async def test_graph_round_trips_through_json():
    with mock_aws():
        seed_sandbox_environment()
        pipeline = AWSIngestionPipeline()
        state = await pipeline.collect()
        topo = TopologyGraph().build_from_state(state)

        data = topo.to_json_dict()
        restored = TopologyGraph.from_json_dict(data)

        assert restored.graph.number_of_nodes() == topo.graph.number_of_nodes()
        assert restored.graph.number_of_edges() == topo.graph.number_of_edges()


def test_diff_reports_added_edges():
    a = TopologyGraph()
    a.graph.add_edge("internet", "sg:sg-1")
    b = TopologyGraph()
    b.graph.add_edge("internet", "sg:sg-1")
    b.graph.add_edge("sg:sg-1", "instance:i-1")

    diff = b.diff(a)
    assert diff["added_edges"] == ["sg:sg-1 -> instance:i-1"]
    assert diff["removed_edges"] == []
