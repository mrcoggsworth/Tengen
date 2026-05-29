"""Persistent left sidebar: dashboard health, agent list, queue depths."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static

_KNOWN_AGENTS = [
    "orchestrator",
    "query_agent",
    "triage",
    "router",
    "containment",
    "enrichment",
    "forwarder",
    "normalizer",
    "cloudtrail_runbook",
    "gcp_audit_runbook",
    "azure_runbook",
    "edr_runbook",
    "k8s_runbook",
]


class HealthSidebar(Widget):
    """Left sidebar showing system health, agents, and queue depths."""

    online: reactive[bool] = reactive(False)
    queues: reactive[list] = reactive(list)

    DEFAULT_CSS = """
    HealthSidebar {
        dock: left;
        width: 28;
        border-right: solid $panel;
        padding: 1 1;
        background: $surface;
        overflow-y: auto;
    }
    HealthSidebar .section-title {
        color: $text-muted;
        text-style: bold;
        padding: 0 0 0 0;
    }
    HealthSidebar .agent-row {
        color: $text;
    }
    HealthSidebar .queue-row {
        color: $text;
    }
    HealthSidebar .live {
        color: $success;
    }
    HealthSidebar .offline {
        color: $error;
    }
    HealthSidebar .divider {
        color: $panel;
        padding: 0;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("", id="health-status")
        yield Static("", id="agents-section")
        yield Static("", id="queues-section")

    def watch_online(self, value: bool) -> None:
        self._render_all()

    def watch_queues(self, value: list) -> None:
        self._render_all()

    def _render_all(self) -> None:
        status_icon = "[green]●[/green] ONLINE" if self.online else "[red]●[/red] OFFLINE"
        self.query_one("#health-status", Static).update(
            f"[bold]Dashboard[/bold]\n{status_icon}\n"
        )

        agent_lines = ["[bold dim]── Agents ─────────────[/bold dim]"]
        dot = "[green]●[/green]" if self.online else "[dim]○[/dim]"
        for name in _KNOWN_AGENTS:
            agent_lines.append(f"{dot} {name}")
        self.query_one("#agents-section", Static).update("\n".join(agent_lines) + "\n")

        if self.queues:
            queue_lines = ["[bold dim]── Queues ─────────────[/bold dim]"]
            for q in self.queues:
                name = q.get("name", "")
                depth = q.get("messages", 0)
                consumers = q.get("consumers", 0)
                color = "yellow" if depth > 10 else "green" if depth == 0 else "white"
                queue_lines.append(
                    f"[{color}]{name[:18]:<18}[/{color}] [dim]{depth:>4}[/dim]"
                )
            self.query_one("#queues-section", Static).update("\n".join(queue_lines))
        else:
            self.query_one("#queues-section", Static).update(
                "[bold dim]── Queues ─────────────[/bold dim]\n[dim]no data[/dim]"
            )
