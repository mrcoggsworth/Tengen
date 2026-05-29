"""Overview screen: key counters and normalization breakdown."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static, DataTable, Label
from textual.containers import Horizontal, Vertical


class MetricCard(Static):
    DEFAULT_CSS = """
    MetricCard {
        border: solid $panel;
        padding: 1 2;
        width: 1fr;
        height: 7;
        content-align: center middle;
        text-align: center;
    }
    MetricCard .card-value {
        text-style: bold;
        color: $accent;
    }
    MetricCard .card-label {
        color: $text-muted;
    }
    """

    def __init__(self, label: str, value: str, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._label = label
        self._value = value

    def render(self) -> str:
        return f"[bold $accent]{self._value}[/bold $accent]\n[dim]{self._label}[/dim]"


class OverviewScreen(Screen):
    """Tab 1 — aggregate security metrics."""

    DEFAULT_CSS = """
    OverviewScreen {
        padding: 1 2;
    }
    #cards-row {
        height: 9;
        margin-bottom: 1;
    }
    #norm-table {
        height: 1fr;
        border: solid $panel;
    }
    #norm-label {
        color: $text-muted;
        margin-bottom: 1;
    }
    """

    def __init__(self, overview: dict, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._overview = overview

    def compose(self) -> ComposeResult:
        o = self._overview
        yield Horizontal(
            MetricCard("Ingested", str(o.get("total_ingested", 0))),
            MetricCard("Processed", str(o.get("total_processed", 0))),
            MetricCard("Errors", str(o.get("total_errors", 0))),
            MetricCard("DLQ", str(o.get("dlq_count", 0))),
            MetricCard("Queues", str(o.get("queue_count", 0))),
            MetricCard("Containments", str(o.get("containment_actions", 0))),
            id="cards-row",
        )
        yield Label("Normalization by source", id="norm-label")
        table = DataTable(id="norm-table", zebra_stripes=True)
        yield table

    def on_mount(self) -> None:
        table = self.query_one("#norm-table", DataTable)
        table.add_columns("Source", "Count")
        norm = self._overview.get("normalization_counts", {})
        if norm:
            for source, count in sorted(norm.items(), key=lambda x: -x[1]):
                table.add_row(source, str(count))
        else:
            table.add_row("[dim]no data[/dim]", "")

    def refresh_data(self, overview: dict) -> None:
        self._overview = overview
        self.query_one("#cards-row").remove()
        # Re-mount via recompose is simplest for the card row
        self.mount(
            Horizontal(
                MetricCard("Ingested", str(overview.get("total_ingested", 0))),
                MetricCard("Processed", str(overview.get("total_processed", 0))),
                MetricCard("Errors", str(overview.get("total_errors", 0))),
                MetricCard("DLQ", str(overview.get("dlq_count", 0))),
                MetricCard("Queues", str(overview.get("queue_count", 0))),
                MetricCard("Containments", str(overview.get("containment_actions", 0))),
                id="cards-row",
            ),
            before=self.query_one("#norm-label"),
        )
        table = self.query_one("#norm-table", DataTable)
        table.clear()
        norm = overview.get("normalization_counts", {})
        if norm:
            for source, count in sorted(norm.items(), key=lambda x: -x[1]):
                table.add_row(source, str(count))
