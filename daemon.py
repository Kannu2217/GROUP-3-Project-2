"""
AeroDrift Daemon — the orchestrator that wires every module together
into the end-to-end autonomous self-healing loop described in the
project brief:

    ingest -> build graph -> detect drift -> generate fix (ast) ->
    execute in sandbox -> re-ingest -> verify heal -> persist ->
    render dashboard -> write incident report

By default this runs inside a `moto` mocked AWS account so the whole
pipeline — including the real ``ec2.revoke_security_group_ingress``
call — executes with zero configuration and zero real cloud risk.
Point ``AeroDriftDaemon`` at a real boto3 session (remove the
``mock_aws()`` context, supply real credentials/region) to run it
against an actual AWS account; no other code changes.
"""

from __future__ import annotations

import argparse
import asyncio
import time

from moto import mock_aws

from aerodrift.codegen.ast_generator import RemediationCodeGenerator
from aerodrift.config import AWS_REGION
from aerodrift.dashboard.cli import AuditDashboard
from aerodrift.graph.topology import TopologyGraph
from aerodrift.ingestion.aws_client import AWSIngestionPipeline
from aerodrift.ingestion.sandbox_seed import inject_chaos_drift, seed_sandbox_environment
from aerodrift.persistence.history_store import HistoryStore
from aerodrift.remediation.executor import SandboxExecutor
from aerodrift.reports.incident_report import generate_incident_report


class AeroDriftDaemon:
    def __init__(self, region_name: str = AWS_REGION, dry_run: bool = False) -> None:
        self.region_name = region_name
        self.dry_run = dry_run
        self.dashboard = AuditDashboard()
        self.history = HistoryStore()
        self.codegen = RemediationCodeGenerator()
        self.executor = SandboxExecutor()
        self.pipeline = AWSIngestionPipeline(region_name=region_name)

    async def ingest_and_build_graph(self) -> tuple[TopologyGraph, list[dict]]:
        state = await self.pipeline.collect()
        topo = TopologyGraph().build_from_state(state)
        return topo, state.security_groups

    async def run_one_cycle(self, chaos_sg_id: str | None = None) -> None:
        self.dashboard.banner()

        # --- 1. Establish / confirm the secure baseline -----------------
        topo, sgs_raw = await self.ingest_and_build_graph()
        baseline_findings = topo.detect_drift(sgs_raw)
        baseline_id = self.history.save_snapshot(topo, label="baseline")
        self.dashboard.console.rule("[bold]Baseline Topology[/bold]")
        self.dashboard.render_topology_tree(topo, drifted_node_ids=set())
        self.dashboard.render_drift_table(baseline_findings)

        # --- 2. Chaos injection (demo only) ------------------------------
        if chaos_sg_id:
            self.dashboard.console.rule("[bold red]Chaos Drift Injector[/bold red]")
            permission = inject_chaos_drift(chaos_sg_id, region_name=self.region_name)
            self.dashboard.console.print(
                f"[yellow]⚡ Injected drift:[/yellow] 0.0.0.0/0 -> "
                f"{permission['FromPort']}/tcp opened on [bold]{chaos_sg_id}[/bold]"
            )

        # --- 3. Re-ingest + detect drift ---------------------------------
        topo, sgs_raw = await self.ingest_and_build_graph()
        findings = topo.detect_drift(sgs_raw)
        drifted_ids = {f"instance:{f.resource_id}" for f in findings}
        self.history.save_snapshot(topo, label="post-drift")

        self.dashboard.console.rule("[bold]Post-Poll Topology[/bold]")
        self.dashboard.render_topology_tree(topo, drifted_node_ids=drifted_ids)
        self.dashboard.render_drift_table(findings)

        # --- 4/5/6. For every finding: generate fix, execute, verify -----
        for finding in findings:
            self.dashboard.console.rule(f"[bold magenta]Remediating {finding.resource_name}[/bold magenta]")

            generated = self.codegen.generate_revoke_ingress(finding, region_name=self.region_name)
            self.dashboard.render_generated_code(generated)

            result = self.executor.run(
                generated.source_code,
                generated.function_name,
                call_kwargs={"region_name": self.region_name},
                dry_run=self.dry_run,
            )
            self.dashboard.render_execution_result(result)

            self.history.log_remediation_event(
                resource_id=finding.resource_id,
                security_group_id=finding.security_group_id,
                function_name=generated.function_name,
                source_code=generated.source_code,
                success=result.success,
                duration_ms=result.duration_ms,
                detail=str(result.return_value),
            )

            # Re-ingest to verify the self-heal actually worked.
            healed = True
            if not self.dry_run:
                post_topo, _ = await self.ingest_and_build_graph()
                healed = not post_topo.is_internet_reachable(f"instance:{finding.resource_id}")
                self.history.save_snapshot(post_topo, label=f"post-heal-{finding.security_group_id}")
            self.dashboard.render_healed_confirmation(finding.resource_name, healed)

            report_path = generate_incident_report(finding, generated, result, healed)
            self.dashboard.console.print(f"[dim]📄 Incident report written to {report_path}[/dim]")

        self.dashboard.console.rule("[bold]Remediation Audit Log[/bold]")
        self.dashboard.render_remediation_log(self.history.list_remediation_events())

    def close(self) -> None:
        self.history.close()


async def _amain(dry_run: bool, no_chaos: bool) -> None:
    with mock_aws():
        ids = seed_sandbox_environment()
        daemon = AeroDriftDaemon(dry_run=dry_run)
        try:
            await daemon.run_one_cycle(chaos_sg_id=None if no_chaos else ids.db_sg_id)
        finally:
            daemon.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AeroDrift self-healing CloudOps daemon demo.")
    parser.add_argument("--dry-run", action="store_true", help="Generate & display fixes but do not execute them.")
    parser.add_argument("--no-chaos", action="store_true", help="Skip the simulated drift injection.")
    args = parser.parse_args()

    start = time.time()
    asyncio.run(_amain(dry_run=args.dry_run, no_chaos=args.no_chaos))
    print(f"\nCycle completed in {time.time() - start:.2f}s")


if __name__ == "__main__":
    main()
