"""Unit tests for the AST remediation code generator and its sandbox executor."""

import ast

import pytest
from moto import mock_aws

from aerodrift.codegen.ast_generator import RemediationCodeGenerator
from aerodrift.graph.topology import DriftFinding
from aerodrift.remediation.executor import RemediationBlocked, SandboxExecutor


def _sample_finding(sg_id: str = "sg-0123456789abcdef0") -> DriftFinding:
    return DriftFinding(
        resource_id="i-0123456789abcdef0",
        resource_name="prod-aurora-postgres-01",
        security_group_id=sg_id,
        protocol="tcp",
        from_port=5432,
        to_port=5432,
        cidr="0.0.0.0/0",
        attack_path=["Internet (0.0.0.0/0)", "sg-rds-aurora-isolated-db", "prod-aurora-postgres-01"],
        blast_score=80,
    )


def test_generated_source_is_valid_python_with_no_leftover_placeholders():
    gen = RemediationCodeGenerator()
    result = gen.generate_revoke_ingress(_sample_finding())

    ast.parse(result.source_code)  # raises SyntaxError if invalid
    assert "__" not in result.source_code.replace("__init__", "")  # no leftover template placeholders
    assert "sg-0123456789abcdef0" in result.source_code
    assert "5432" in result.source_code
    assert result.function_name == "remediate_drift_sg_0123456789abcdef0"


def test_generated_function_is_unique_per_security_group():
    gen = RemediationCodeGenerator()
    r1 = gen.generate_revoke_ingress(_sample_finding("sg-aaa"))
    r2 = gen.generate_revoke_ingress(_sample_finding("sg-bbb"))
    assert r1.function_name != r2.function_name


def test_sandbox_executes_generated_fix_against_moto():
    with mock_aws():
        import boto3

        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        sg = ec2.create_security_group(GroupName="test-db-sg", Description="d", VpcId=vpc["VpcId"])
        sg_id = sg["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )

        gen = RemediationCodeGenerator()
        generated = gen.generate_revoke_ingress(_sample_finding(sg_id))

        executor = SandboxExecutor()
        result = executor.run(generated.source_code, generated.function_name, {"region_name": "us-east-1"})

        assert result.success is True
        assert result.error is None

        rule_still_open = any(
            r.get("CidrIp") == "0.0.0.0/0"
            for perm in ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]["IpPermissions"]
            for r in perm.get("IpRanges", [])
        )
        assert rule_still_open is False


def test_sandbox_blocks_disallowed_imports():
    malicious_source = "import os\n\ndef remediate_drift_evil():\n    return os.system('echo hi')\n"
    executor = SandboxExecutor()
    with pytest.raises(RemediationBlocked):
        executor.run(malicious_source, "remediate_drift_evil")


def test_sandbox_dry_run_does_not_call_aws():
    gen = RemediationCodeGenerator()
    generated = gen.generate_revoke_ingress(_sample_finding())
    executor = SandboxExecutor()
    result = executor.run(generated.source_code, generated.function_name, dry_run=True)
    assert result.dry_run is True
    assert result.return_value["status"] == "DRY_RUN"
