"""Tengen TUI — terminal interface for monitoring and interacting with agents."""
from __future__ import annotations

import argparse

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Header, Footer, TabbedContent, TabPane

from tengen.tui.api_client import DashboardClient
from tengen.tui.widgets.sidebar import HealthSidebar
from tengen.tui.screens.overview import OverviewScreen
from tengen.tui.screens.agents import AgentsScreen
from tengen.tui.screens.query import QueryScreen
from tengen.tui.screens.runbooks import RunbooksScreen

_REFRESH_INTERVAL = 10.0


class TengenTUI(App):
    """Main TUI application."""

    TITLE = "Tengen"
    SUB_TITLE = "Security Agent Monitor"

    CSS = """
    Screen {
        background: #1a1b26;
        color: #c0caf5;
    }
    Header {
        background: #24283b;
        color: #7aa2f7;
        text-style: bold;
    }
    Footer {
        background: #24283b;
        color: #565f89;
    }
    TabbedContent {
        height: 1fr;
    }
    TabbedContent ContentSwitcher {
        height: 1fr;
    }
    TabPane {
        height: 1fr;
        padding: 0;
    }
    HealthSidebar {
        background: #1f2335;
        border-right: solid #2a2b3d;
        color: #a9b1d6;
    }
    #main-layout {
        layout: horizontal;
        height: 1fr;
    }
    #content-area {
        width: 1fr;
        height: 1fr;
    }
    DataTable {
        background: #1a1b26;
        color: #c0caf5;
    }
    DataTable > .datatable--header {
        background: #24283b;
        color: #7aa2f7;
        text-style: bold;
    }
    DataTable > .datatable--cursor {
        background: #2a2b3d;
    }
    DataTable > .datatable--zebra-stripe-even {
        background: #1f2335;
    }
    Input {
        background: #24283b;
        color: #c0caf5;
        border: solid #3b4261;
    }
    Input:focus {
        border: solid #7aa2f7;
    }
    RichLog {
        background: #1a1b26;
        color: #c0caf5;
    }
    MetricCard {
        background: #1f2335;
        border: solid #2a2b3d;
        color: #c0caf5;
    }
    TabbedContent Tabs {
        background: #24283b;
    }
    TabbedContent Tab {
        color: #565f89;
    }
    TabbedContent Tab.-active {
        color: #7aa2f7;
        background: #1a1b26;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("r", "refresh", "Refresh"),
        Binding("1", "switch_tab('tab-overview')", "Overview"),
        Binding("2", "switch_tab('tab-agents')", "Agents"),
        Binding("3", "switch_tab('tab-query')", "Query"),
        Binding("4", "switch_tab('tab-runbooks')", "Runbooks"),
    ]

    def __init__(self, dashboard_url: str = "http://localhost:8080", **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._client = DashboardClient(base_url=dashboard_url)
        self._online = False
        self._queues: list[dict] = []
        self._overview: dict = {}
        self._runbooks: list[dict] = []
        self._routes: list[dict] = []

    def compose(self) -> ComposeResult:
        yield Header()
        from textual.containers import Horizontal
        with Horizontal(id="main-layout"):
            yield HealthSidebar(id="sidebar")
            with TabbedContent(id="main-tabs"):
                with TabPane("Overview", id="tab-overview"):
                    yield OverviewScreen(overview={}, id="overview-screen")
                with TabPane("Agents", id="tab-agents"):
                    yield AgentsScreen(queues=[], online=False, id="agents-screen")
                with TabPane("Query", id="tab-query"):
                    yield QueryScreen(id="query-screen")
                with TabPane("Runbooks", id="tab-runbooks"):
                    yield RunbooksScreen(runbooks=[], routes=[], id="runbooks-screen")
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(_REFRESH_INTERVAL, self.action_refresh)
        self.call_after_refresh(self.action_refresh)

    def action_refresh(self) -> None:
        self.run_worker(self._fetch_and_update, exclusive=True, thread=True)

    def action_switch_tab(self, tab_id: str) -> None:
        self.query_one("#main-tabs", TabbedContent).active = tab_id

    def _fetch_and_update(self) -> None:
        online = self._client.healthz()
        queues = self._client.get_queues() if online else []
        overview = self._client.get_overview() if online else {}
        runbooks = self._client.get_runbooks() if online else []
        routes = self._client.get_routes() if online else []

        self._online = online
        self._queues = queues
        self._overview = overview
        self._runbooks = runbooks
        self._routes = routes

        self.app.call_from_thread(self._apply_updates, online, queues, overview, runbooks, routes)

    def _apply_updates(
        self,
        online: bool,
        queues: list[dict],
        overview: dict,
        runbooks: list[dict],
        routes: list[dict],
    ) -> None:
        sidebar = self.query_one("#sidebar", HealthSidebar)
        sidebar.online = online
        sidebar.queues = queues

        self.query_one("#overview-screen", OverviewScreen).refresh_data(overview)
        self.query_one("#agents-screen", AgentsScreen).refresh_data(queues, online)
        self.query_one("#runbooks-screen", RunbooksScreen).refresh_data(runbooks, routes)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tengen-tui",
        description="Tengen security agent monitor (TUI)",
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8080",
        metavar="URL",
        help="Dashboard API base URL (default: http://localhost:8080)",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_arg_parser().parse_args(argv)
    TengenTUI(dashboard_url=args.url).run()
