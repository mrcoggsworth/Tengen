"""Query screen: natural-language questions answered by query_agent."""
from __future__ import annotations

import os
import threading
from typing import Any

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import RichLog, Input, Label
from textual.containers import Vertical


class QueryScreen(Screen):
    """Tab 3 — ask security questions via the query_agent."""

    DEFAULT_CSS = """
    QueryScreen {
        padding: 1 2;
    }
    #query-log {
        height: 1fr;
        border: solid $panel;
        margin-bottom: 1;
    }
    #query-hint {
        color: $text-muted;
        margin-bottom: 0;
    }
    #query-input {
        border: solid $accent;
    }
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._busy = False

    def compose(self) -> ComposeResult:
        yield RichLog(id="query-log", highlight=True, markup=True, wrap=True)
        yield Label("Ask a natural-language security question (Enter to submit):", id="query-hint")
        yield Input(placeholder="e.g. Show me IAM changes in the last 24 hours …", id="query-input")

    def on_mount(self) -> None:
        log = self.query_one("#query-log", RichLog)
        log.write("[dim]Query agent ready. Type a question below and press Enter.[/dim]")
        if not os.environ.get("GOOGLE_API_KEY"):
            log.write(
                "[yellow]⚠ GOOGLE_API_KEY is not set — queries will fail. "
                "Export the key and restart.[/yellow]"
            )

    def on_input_submitted(self, event: Input.Submitted) -> None:
        question = event.value.strip()
        if not question or self._busy:
            return
        event.input.clear()
        self._submit_query(question)

    def _submit_query(self, question: str) -> None:
        log = self.query_one("#query-log", RichLog)
        log.write(f"\n[bold cyan]>[/bold cyan] {question}")
        self._busy = True

        def _run() -> None:
            try:
                result = self._call_agent(question)
                self.app.call_from_thread(self._show_result, result)
            except Exception as exc:
                self.app.call_from_thread(self._show_result, f"[red]Error: {exc}[/red]")

        threading.Thread(target=_run, daemon=True, name="query-worker").start()

    def _call_agent(self, question: str) -> str:
        import asyncio
        return asyncio.run(self._call_agent_async(question))

    async def _call_agent_async(self, question: str) -> str:
        try:
            from google.adk.runners import Runner
            from google.adk.sessions import InMemorySessionService
            from google.genai import types as genai_types
            from tengen.agents.query import query_agent

            session_service = InMemorySessionService()
            session = await session_service.create_session(
                app_name="tengen-tui", user_id="tui-user"
            )
            runner = Runner(
                agent=query_agent,
                app_name="tengen-tui",
                session_service=session_service,
            )
            content = genai_types.Content(
                role="user",
                parts=[genai_types.Part(text=question)],
            )
            response_parts: list[str] = []
            async for event in runner.run_async(
                user_id="tui-user",
                session_id=session.id,
                new_message=content,
            ):
                if event.is_final_response() and event.content and event.content.parts:
                    for part in event.content.parts:
                        if hasattr(part, "text") and part.text:
                            response_parts.append(part.text)
            return "\n".join(response_parts) if response_parts else "[dim]No response.[/dim]"
        except ImportError as exc:
            return f"[red]Import error: {exc}[/red]"

    def _show_result(self, result: str) -> None:
        log = self.query_one("#query-log", RichLog)
        log.write(result)
        self._busy = False
