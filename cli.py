"""
Audit Dashboard — a Rich-powered terminal UI that renders the cloud
topology as a tree, highlights drifted resources in red, shows the
AST-generated remediation source, and logs every autonomous action
AeroDrift takes.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from aerodrift.codegen.ast_generator import GeneratedRemediation
from aerodrift.graph.topology import DriftFinding, TopologyGraph
from aerodrift.remediation.executor import ExecutionResult

NODE_ICONS = {
    "internet": "🌐",
    "internet_gateway": "🚪",
    "route_table": "🛣️ ",
    "subnet": "🧩",
    "security_group": "🔒",
    "instance": "💻",
    "database": "🗄️ ",
}


class AuditDashboard:
    def __init__(self) -> None:
        self.console = Console()

    def banner(self) -> None:
        self.console.print(
            Panel.fit(
                "[bold cyan]AeroDrift[/bold cyan] [white]v1.4[/white]  —  "
                "[dim]Agentic Cloud Topology & AST Remediation Graph[/dim]",
                border_style="cyan",
            )
        )

    def render_topology_tree(self, topo: TopologyGraph, drifted_node_ids: set[str]) -> None:
        tree = Tree("[bold]🌐 Cloud Topology[/bold]")
        graph = topo.graph
        roots = [n for n in graph.nodes if graph.nodes[n].get("node_type") == "internet"]
        visited: set[str] = set()

        def add_children(parent_tree: Tree, node: str) -> None:
            if node in visited:
                return
            visited.add(node)
            for _, child in sorted(graph.out_edges(node)):
                node_type = graph.nodes[child].get("node_type", "")
                label = graph.nodes[child].get("label", child)
                icon = NODE_ICONS.get(node_type, "•")
                is_drifted = child in drifted_node_ids
                style = "bold red" if is_drifted else "white"
                tag = " [red bold]DRIFTED[/red bold]" if is_drifted else ""
                branch = parent_tree.add(Text.from_markup(f"{icon} [{style}]{label}[/{style}]{tag}"))
                add_children(branch, child)

        for root in roots:
            root_branch = tree.add(f"🌐 [bold]{graph.nodes[root].get('label', root)}[/bold]")
            add_children(root_branch, root)

        self.console.print(tree)

    def render_drift_table(self, findings: list[DriftFinding]) -> None:
        if not findings:
            self.console.print("[bold green]✔ No drift detected — topology matches approved baseline.[/bold green]")
            return

        table = Table(title="⚠ Drift Findings", show_lines=True, border_style="red")
        table.add_column("Severity", style="bold red")
        table.add_column("Resource")
        table.add_column("Security Group")
        table.add_column("Rule")
        table.add_column("Blast Score")
        table.add_column("Attack Path")

        for f in findings:
            table.add_row(
                f.severity,
                f.resource_name,
                f.security_group_id,
                f"{f.protocol}/{f.from_port}-{f.to_port} from {f.cidr}",
                f"{f.blast_score}/100",
                f.attack_path_str(),
            )
        self.console.print(table)

    def render_generated_code(self, generated: GeneratedRemediation) -> None:
        self.console.print(
            Panel(
                Syntax(generated.source_code, "python", theme="monokai", line_numbers=True),
                title=f"🤖 AST Remediation Engine — {generated.function_name}() "
                f"(synthesized in {generated.synthesis_ms:.2f}ms, {generated.ast_node_count} AST nodes)",
                border_style="magenta",
            )
        )

    def render_execution_result(self, result: ExecutionResult) -> None:
        style = "green" if result.success else "red"
        status = "✔ SUCCESS" if result.success else "✘ FAILED"
        self.console.print(
            Panel(
                f"[{style}]{status}[/{style}]  function={result.function_name}  "
                f"duration={result.duration_ms:.2f}ms  dry_run={result.dry_run}\n"
                f"[dim]{result.stdout.strip()}[/dim]"
                + (f"\n[red]{result.error}[/red]" if result.error else ""),
                title="⚡ Execution Sandbox",
                border_style=style,
            )
        )

    def render_healed_confirmation(self, resource_name: str, healed: bool) -> None:
        if healed:
            self.console.print(
                f"[bold green]✔ Self-heal verified:[/bold green] {resource_name} is no longer "
                f"reachable from the Internet. Graph re-evaluated."
            )
        else:
            self.console.print(
                f"[bold red]✘ Self-heal NOT verified:[/bold red] {resource_name} is still "
                f"Internet-reachable after remediation — escalating to human operator."
            )

    def render_remediation_log(self, events: list[dict]) -> None:
        table = Table(title="📜 Remediation Audit Log", border_style="blue")
        table.add_column("Timestamp")
        table.add_column("Resource")
        table.add_column("Function")
        table.add_column("Result")
        table.add_column("Duration")
        import datetime

        for e in events:
            ts = datetime.datetime.fromtimestamp(e["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            result = "[green]SUCCESS[/green]" if e["success"] else "[red]FAILED[/red]"
            table.add_row(ts, e["resource_id"], e["function_name"], result, f"{e['duration_ms']:.1f}ms")
        self.console.print(table)
