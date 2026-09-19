"""
AeroDrift — Agentic Cloud Topology & AST Remediation Graph
============================================================

A self-healing CloudOps daemon that:
  1. Ingests live AWS state concurrently (boto3 + asyncio)
  2. Models the cloud as a directed reachability graph (NetworkX)
  3. Detects unapproved network paths (e.g. Internet -> private DB)
  4. Synthesizes exact-fix remediation code on the fly (Python `ast`)
  5. Executes the fix in a locked-down sandbox and verifies the heal
  6. Renders a live audit dashboard (Rich) and persists history (SQLite)

See docs/ARCHITECTURE.md for the full design.
"""

__version__ = "1.4.0"
__all__ = ["__version__"]
