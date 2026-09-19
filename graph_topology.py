"""
Topology Engine — models the cloud account as a directed reachability
graph in NetworkX and answers the one question that matters for this
project: *"Is there a path from the public Internet to a private
database?"*

Graph model
-----------
Nodes (id -> type):
    "internet"                node_type=internet
    "igw:<id>"                node_type=internet_gateway
    "rtb:<id>"                node_type=route_table
    "subnet:<id>"             node_type=subnet
    "sg:<id>"                 node_type=security_group
    "instance:<id>"           node_type=instance | database

Edges (A -> B means "traffic can flow from A to B"):
    internet    -> igw          always, for every attached Internet Gateway
    igw         -> rtb          only if that route table has an explicit
                                 0.0.0.0/0 route targeting the IGW
                                 (this is exactly what a "rogue route
                                 table entry" drift creates)
    rtb         -> subnet       structural: subnet is associated with
                                 that route table
    subnet      -> sg           only if the SG governs an instance in
                                 that subnet *and* the SG has an open
                                 (0.0.0.0/0) ingress rule — i.e. once a
                                 packet is routed into the subnet, an
                                 open SG lets it through
    internet    -> sg           direct "policy bypass" edge, added
                                 whenever a security group has an open
                                 ingress rule — this is what an
                                 "accidental 0.0.0.0/0 SG rule" drift
                                 creates, independent of routing. CSPM
                                 tools flag this as CRITICAL on its own
                                 (defense-in-depth violation) even
                                 before full network exploitability.
    sg          -> instance     structural: SG governs the instance

A resource is "internet-exposed" iff ``nx.has_path(graph, "internet",
node_id)`` is True. Database-tagged nodes reachable this way are
CRITICAL drift findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from aerodrift.config import (
    DATABASE_TAG_KEY,
    DATABASE_TAG_VALUE,
    INTERNET_CIDR,
    NODE_TYPE_DATABASE,
    NODE_TYPE_IGW,
    NODE_TYPE_INSTANCE,
    NODE_TYPE_INTERNET,
    NODE_TYPE_ROUTE_TABLE,
    NODE_TYPE_SECURITY_GROUP,
    NODE_TYPE_SUBNET,
)
from aerodrift.ingestion.aws_client import CloudState

INTERNET_NODE = "internet"


@dataclass
class DriftFinding:
    """One CRITICAL/HIGH finding: an unapproved Internet -> resource path."""

    resource_id: str
    resource_name: str
    security_group_id: str
    protocol: str
    from_port: int
    to_port: int
    cidr: str
    attack_path: list[str]
    blast_score: int
    severity: str = "CRITICAL"

    def attack_path_str(self) -> str:
        return " -> ".join(self.attack_path)


def _tag_value(tags: list[dict[str, Any]] | None, key: str) -> str | None:
    for tag in tags or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


class TopologyGraph:
    """Wraps a ``networkx.DiGraph`` built from an ingested ``CloudState``."""

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    def build_from_state(self, state: CloudState) -> "TopologyGraph":
        g = nx.DiGraph()
        g.add_node(INTERNET_NODE, node_type=NODE_TYPE_INTERNET, label="Internet (0.0.0.0/0)")

        # 1. Internet Gateways
        for igw in state.internet_gateways:
            igw_id = igw["InternetGatewayId"]
            node = f"igw:{igw_id}"
            g.add_node(node, node_type=NODE_TYPE_IGW, label=igw_id)
            g.add_edge(INTERNET_NODE, node, reason="internet_gateway_attached")

        # 2. Route tables with a public (0.0.0.0/0) route to an IGW
        subnet_to_rtbs: dict[str, list[str]] = {}
        for rtb in state.route_tables:
            rtb_id = rtb["RouteTableId"]
            rtb_node = f"rtb:{rtb_id}"
            has_public_route = any(
                route.get("DestinationCidrBlock") == INTERNET_CIDR
                and route.get("GatewayId", "").startswith("igw-")
                for route in rtb.get("Routes", [])
            )
            g.add_node(
                rtb_node,
                node_type=NODE_TYPE_ROUTE_TABLE,
                label=rtb_id,
                has_public_route=has_public_route,
            )
            if has_public_route:
                for route in rtb["Routes"]:
                    if route.get("DestinationCidrBlock") == INTERNET_CIDR and route.get(
                        "GatewayId", ""
                    ).startswith("igw-"):
                        g.add_edge(f"igw:{route['GatewayId']}", rtb_node, reason="public_route")

            for assoc in rtb.get("Associations", []):
                subnet_id = assoc.get("SubnetId")
                if subnet_id:
                    subnet_to_rtbs.setdefault(subnet_id, []).append(rtb_id)

        # 3. Subnets, wired to their route table(s)
        for subnet in state.subnets:
            subnet_id = subnet["SubnetId"]
            subnet_node = f"subnet:{subnet_id}"
            name = _tag_value(subnet.get("Tags"), "Name") or subnet_id
            g.add_node(subnet_node, node_type=NODE_TYPE_SUBNET, label=name)
            for rtb_id in subnet_to_rtbs.get(subnet_id, []):
                g.add_edge(f"rtb:{rtb_id}", subnet_node, reason="route_table_association")

        # 4. Security groups
        instance_subnet: dict[str, str] = {}
        instance_sgs: dict[str, list[str]] = {}
        for inst in state.instances:
            iid = inst["InstanceId"]
            instance_subnet[iid] = inst.get("SubnetId", "")
            instance_sgs[iid] = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]

        sg_open_to_internet: dict[str, list[dict[str, Any]]] = {}
        for sg in state.security_groups:
            sg_id = sg["GroupId"]
            sg_node = f"sg:{sg_id}"
            g.add_node(sg_node, node_type=NODE_TYPE_SECURITY_GROUP, label=sg.get("GroupName", sg_id))

            open_perms = []
            for perm in sg.get("IpPermissions", []):
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == INTERNET_CIDR:
                        open_perms.append(perm)
                        # Direct policy-bypass edge: internet -> sg
                        g.add_edge(
                            INTERNET_NODE,
                            sg_node,
                            reason="open_ingress_rule",
                            protocol=perm.get("IpProtocol"),
                            from_port=perm.get("FromPort"),
                            to_port=perm.get("ToPort"),
                        )
            if open_perms:
                sg_open_to_internet[sg_id] = open_perms

        # subnet -> sg edges, only for SGs that are open AND govern an
        # instance that actually lives in that subnet.
        for iid, sg_ids in instance_sgs.items():
            subnet_id = instance_subnet.get(iid)
            if not subnet_id:
                continue
            for sg_id in sg_ids:
                if sg_id in sg_open_to_internet:
                    g.add_edge(f"subnet:{subnet_id}", f"sg:{sg_id}", reason="subnet_routed_to_open_sg")

        # 5. Instances (+ RDS db instances modelled the same way)
        for inst in state.instances:
            iid = inst["InstanceId"]
            is_db = _tag_value(inst.get("Tags"), DATABASE_TAG_KEY) == DATABASE_TAG_VALUE
            node_type = NODE_TYPE_DATABASE if is_db else NODE_TYPE_INSTANCE
            name = _tag_value(inst.get("Tags"), "Name") or iid
            node = f"instance:{iid}"
            g.add_node(node, node_type=node_type, label=name, is_database=is_db)
            for sg in inst.get("SecurityGroups", []):
                g.add_edge(f"sg:{sg['GroupId']}", node, reason="sg_governs_instance")

        for db in state.db_instances:
            db_id = db.get("DBInstanceIdentifier")
            if not db_id:
                continue
            node = f"instance:{db_id}"
            g.add_node(node, node_type=NODE_TYPE_DATABASE, label=db_id, is_database=True)
            for sg in db.get("VpcSecurityGroups", []):
                g.add_edge(f"sg:{sg['VpcSecurityGroupId']}", node, reason="sg_governs_instance")

        self.graph = g
        return self

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def database_nodes(self) -> list[str]:
        return [n for n, d in self.graph.nodes(data=True) if d.get("is_database")]

    def find_path(self, source: str, target: str) -> list[str] | None:
        try:
            return nx.shortest_path(self.graph, source, target)
        except (nx.NodeNotFound, nx.NetworkXNoPath):
            return None

    def is_internet_reachable(self, node: str) -> bool:
        return self.graph.has_node(node) and nx.has_path(self.graph, INTERNET_NODE, node)

    def detect_drift(self, security_groups_raw: list[dict[str, Any]]) -> list[DriftFinding]:
        """
        Walk every database node; if it is reachable from the Internet,
        emit a DriftFinding describing the exact offending ingress rule
        and the attack path NetworkX found.
        """
        findings: list[DriftFinding] = []
        sg_lookup = {sg["GroupId"]: sg for sg in security_groups_raw}

        for db_node in self.database_nodes():
            if not self.is_internet_reachable(db_node):
                continue
            path = self.find_path(INTERNET_NODE, db_node)
            if not path:
                continue

            # The offending SG is the last sg:<id> node on the path.
            sg_node = next((n for n in reversed(path) if n.startswith("sg:")), None)
            sg_id = sg_node.split(":", 1)[1] if sg_node else "unknown"
            sg_raw = sg_lookup.get(sg_id, {})

            offending_perm = None
            for perm in sg_raw.get("IpPermissions", []):
                if any(r.get("CidrIp") == INTERNET_CIDR for r in perm.get("IpRanges", [])):
                    offending_perm = perm
                    break

            resource_id = db_node.split(":", 1)[1]
            resource_name = self.graph.nodes[db_node].get("label", resource_id)

            blast_score = 80 if len(path) <= 3 else 60  # direct SG bypass scores higher
            findings.append(
                DriftFinding(
                    resource_id=resource_id,
                    resource_name=resource_name,
                    security_group_id=sg_id,
                    protocol=(offending_perm or {}).get("IpProtocol", "tcp"),
                    from_port=(offending_perm or {}).get("FromPort", 0),
                    to_port=(offending_perm or {}).get("ToPort", 0),
                    cidr=INTERNET_CIDR,
                    attack_path=[self.graph.nodes[n].get("label", n) for n in path],
                    blast_score=blast_score,
                )
            )
        return findings

    # ------------------------------------------------------------------
    # Serialization (for SQLite persistence / diffing)
    # ------------------------------------------------------------------
    def to_json_dict(self) -> dict[str, Any]:
        return nx.node_link_data(self.graph, edges="edges")

    @classmethod
    def from_json_dict(cls, data: dict[str, Any]) -> "TopologyGraph":
        tg = cls()
        tg.graph = nx.node_link_graph(data, edges="edges")
        return tg

    def diff(self, other: "TopologyGraph") -> dict[str, list[str]]:
        """Structural diff between this graph and an earlier snapshot."""
        this_edges = set(self.graph.edges())
        other_edges = set(other.graph.edges())
        return {
            "added_edges": [f"{a} -> {b}" for a, b in sorted(this_edges - other_edges)],
            "removed_edges": [f"{a} -> {b}" for a, b in sorted(other_edges - this_edges)],
        }
