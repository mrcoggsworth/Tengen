"""Agents screen: per-agent queue depth and consumer counts."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Label

_AGENT_QUEUE_MAP = {
    "orchestrator": "alerts",
    "triage": "alerts.triage",
    "router": "alerts",
    "normalizer": "alerts",
    "containment": "alerts.containment",
    "enrichment": "alerts.enriched",
    "forwarder": "alerts.enriched",
    "cloudtrail_runbook": "alerts.aws",
    "gcp_audit_runbook": "alerts.gcp",
    "azure_runbook": "alerts.azure",
    "edr_runbook": "alerts.edr",
    "k8s_runbook": "alerts.k8s",
    "query_agent": "(on-demand)",
}


class AgentsScreen(Screen):
    """Tab 2 — agent status and associated queue depths."""

    DEFAULT_CSS = """
    AgentsScreen {
        padding: 1 2;
    }
    #agents-table {
        height: 1fr;
        border: solid $panel;
    }
    #agents-label {
        color: $text-muted;
        margin-bottom: 1;
    }
    """

    def __init__(self, queues: list[dict], online: bool, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._queues = queues
        self._online = online

    def _queue_map(self) -> dict[str, dict]:
        return {q["name"]: q for q in self._queues}

    def compose(self) -> ComposeResult:
        yield Label("Agent status is proxied through dashboard health. Queue depths are live.", id="agents-label")
        yield DataTable(id="agents-table", zebra_stripes=True)

    def on_mount(self) -> None:
        self._build_table()

    def _build_table(self) -> None:
        table = self.query_one("#agents-table", DataTable)
        table.clear(columns=True)
        table.add_columns("Agent", "Queue", "Depth", "Consumers", "Status")
        qmap = self._queue_map()
        status = "[green]LIVE[/green]" if self._online else "[red]OFFLINE[/red]"
        for agent, queue_name in _AGENT_QUEUE_MAP.items():
            q = qmap.get(queue_name, {})
            depth = str(q.get("messages", "—")) if q else "—"
            consumers = str(q.get("consumers", "—")) if q else "—"
            table.add_row(agent, queue_name, depth, consumers, status)

    def refresh_data(self, queues: list[dict], online: bool) -> None:
        self._queues = queues
        self._online = online
        self._build_table()
