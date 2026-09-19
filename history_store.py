"""
Persistence layer — stores every topology snapshot AeroDrift ever
builds (and every remediation it performs) in a local SQLite database,
so an operator can later diff the cloud's shape between any two
points in time ("what did our network topology look like right before
the incident, and right after the auto-heal?").
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

from aerodrift.config import HISTORY_DB_PATH
from aerodrift.graph.topology import TopologyGraph

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    label TEXT NOT NULL,
    node_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL,
    graph_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS remediation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    resource_id TEXT NOT NULL,
    security_group_id TEXT NOT NULL,
    function_name TEXT NOT NULL,
    source_code TEXT NOT NULL,
    success INTEGER NOT NULL,
    duration_ms REAL NOT NULL,
    detail TEXT
);
"""


@dataclass
class Snapshot:
    id: int
    timestamp: float
    label: str
    node_count: int
    edge_count: int
    graph: TopologyGraph


class HistoryStore:
    def __init__(self, db_path: str = HISTORY_DB_PATH) -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------
    def save_snapshot(self, graph: TopologyGraph, label: str) -> int:
        data = graph.to_json_dict()
        cur = self._conn.execute(
            "INSERT INTO snapshots (timestamp, label, node_count, edge_count, graph_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (time.time(), label, graph.graph.number_of_nodes(), graph.graph.number_of_edges(), json.dumps(data)),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_snapshot(self, snapshot_id: int) -> Snapshot | None:
        row = self._conn.execute(
            "SELECT id, timestamp, label, node_count, edge_count, graph_json FROM snapshots WHERE id = ?",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            return None
        return Snapshot(
            id=row[0],
            timestamp=row[1],
            label=row[2],
            node_count=row[3],
            edge_count=row[4],
            graph=TopologyGraph.from_json_dict(json.loads(row[5])),
        )

    def latest_snapshot(self) -> Snapshot | None:
        row = self._conn.execute("SELECT id FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
        return self.get_snapshot(row[0]) if row else None

    def list_snapshots(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, timestamp, label, node_count, edge_count FROM snapshots ORDER BY id"
        ).fetchall()
        return [
            {"id": r[0], "timestamp": r[1], "label": r[2], "node_count": r[3], "edge_count": r[4]}
            for r in rows
        ]

    def diff_snapshots(self, id_a: int, id_b: int) -> dict[str, list[str]]:
        a = self.get_snapshot(id_a)
        b = self.get_snapshot(id_b)
        if a is None or b is None:
            raise ValueError("Both snapshot ids must exist")
        return b.graph.diff(a.graph)

    # ------------------------------------------------------------------
    def log_remediation_event(
        self,
        resource_id: str,
        security_group_id: str,
        function_name: str,
        source_code: str,
        success: bool,
        duration_ms: float,
        detail: str = "",
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO remediation_events "
            "(timestamp, resource_id, security_group_id, function_name, source_code, success, duration_ms, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), resource_id, security_group_id, function_name, source_code, int(success), duration_ms, detail),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_remediation_events(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, timestamp, resource_id, security_group_id, function_name, success, duration_ms, detail "
            "FROM remediation_events ORDER BY id"
        ).fetchall()
        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "resource_id": r[2],
                "security_group_id": r[3],
                "function_name": r[4],
                "success": bool(r[5]),
                "duration_ms": r[6],
                "detail": r[7],
            }
            for r in rows
        ]
