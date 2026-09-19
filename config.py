"""
Central configuration: AWS region, resource naming, and the *approved
security baseline* that the drift detector compares live state against.

In a real deployment this baseline would be sourced from the last
`terraform plan` state or an OPA/Sentinel policy bundle. For this
project it is expressed directly as data so the whole pipeline runs
without any external policy engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field

AWS_REGION = "us-east-1"

INTERNET_CIDR = "0.0.0.0/0"

# Logical node-type tags used throughout the NetworkX graph.
NODE_TYPE_INTERNET = "internet"
NODE_TYPE_IGW = "internet_gateway"
NODE_TYPE_ROUTE_TABLE = "route_table"
NODE_TYPE_SUBNET = "subnet"
NODE_TYPE_SECURITY_GROUP = "security_group"
NODE_TYPE_INSTANCE = "instance"
NODE_TYPE_DATABASE = "database"


@dataclass(frozen=True)
class IngressRule:
    """One approved (or observed) security-group ingress rule."""

    security_group_id: str
    protocol: str
    from_port: int
    to_port: int
    cidr: str

    def is_public(self) -> bool:
        return self.cidr == INTERNET_CIDR

    def key(self) -> tuple:
        return (self.security_group_id, self.protocol, self.from_port, self.to_port, self.cidr)


@dataclass
class SecurityBaseline:
    """
    The set of ingress rules considered *approved* for the environment.

    Anything observed in live state that is not in this set — and that
    also creates a path from the Internet to a database-tagged
    resource — is flagged as CRITICAL drift and is a candidate for
    autonomous remediation.
    """

    approved_rules: list[IngressRule] = field(default_factory=list)

    def is_approved(self, rule: IngressRule) -> bool:
        return rule.key() in {r.key() for r in self.approved_rules}


# Tag key used to mark an EC2 instance / RDS resource as a database
# workload for the purposes of blast-radius scoring.
DATABASE_TAG_KEY = "Role"
DATABASE_TAG_VALUE = "database"

# SQLite file used by the persistence layer.
HISTORY_DB_PATH = "aerodrift_history.sqlite3"

# Directory where generated incident reports are written.
REPORTS_DIR = "incident_reports"
