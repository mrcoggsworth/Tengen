"""Runbooks screen: browse available runbooks and routing rules."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, TabbedContent, TabPane, Label


class RunbooksScreen(Screen):
    """Tab 4 — runbooks catalog and routing rules."""

    DEFAULT_CSS = """
    RunbooksScreen {
        padding: 1 2;
    }
    #runbooks-tabs {
        height: 1fr;
    }
    .rb-table {
        height: 1fr;
        border: solid $panel;
    }
    #rb-hint {
        color: $text-muted;
        margin-bottom: 1;
    }
    """

    def __init__(self, runbooks: list[dict], routes: list[dict], **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._runbooks = runbooks
        self._routes = routes

    def compose(self) -> ComposeResult:
        yield Label(
            f"{len(self._runbooks)} runbooks · {len(self._routes)} routes",
            id="rb-hint",
        )
        with TabbedContent(id="runbooks-tabs"):
            with TabPane("Runbooks", id="tab-runbooks"):
                yield DataTable(id="runbooks-table", classes="rb-table", zebra_stripes=True)
            with TabPane("Routes", id="tab-routes"):
                yield DataTable(id="routes-table", classes="rb-table", zebra_stripes=True)

    def on_mount(self) -> None:
        rb = self.query_one("#runbooks-table", DataTable)
        rb.add_columns("Name", "Source Queue", "Module")
        for r in self._runbooks:
            rb.add_row(
                r.get("name", ""),
                r.get("source_queue", ""),
                r.get("module", ""),
            )
        if not self._runbooks:
            rb.add_row("[dim]no runbooks discovered[/dim]", "", "")

        rt = self.query_one("#routes-table", DataTable)
        rt.add_columns("Name", "Queue", "Description")
        for r in self._routes:
            rt.add_row(
                r.get("name", ""),
                r.get("queue", ""),
                r.get("description", ""),
            )
        if not self._routes:
            rt.add_row("[dim]no routes discovered[/dim]", "", "")

    def refresh_data(self, runbooks: list[dict], routes: list[dict]) -> None:
        self._runbooks = runbooks
        self._routes = routes
        self.query_one("#rb-hint", Label).update(
            f"{len(runbooks)} runbooks · {len(routes)} routes"
        )
        rb = self.query_one("#runbooks-table", DataTable)
        rb.clear()
        for r in runbooks:
            rb.add_row(r.get("name", ""), r.get("source_queue", ""), r.get("module", ""))

        rt = self.query_one("#routes-table", DataTable)
        rt.clear()
        for r in routes:
            rt.add_row(r.get("name", ""), r.get("queue", ""), r.get("description", ""))
