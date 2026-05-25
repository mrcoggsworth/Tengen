"""MCP stdio server for GCP Audit Log retrieval."""
import asyncio
import json

from google.cloud import logging as gcp_logging
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("tengen-gcp-audit")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="get_gcp_audit_logs",
            description="Retrieve recent GCP Audit Log entries for a project and time window",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "start_time": {"type": "string", "description": "RFC 3339 start time"},
                    "end_time": {"type": "string", "description": "RFC 3339 end time"},
                    "log_filter": {
                        "type": "string",
                        "description": "Optional additional filter expression",
                    },
                    "max_results": {"type": "integer", "default": 50},
                },
                "required": ["project_id", "start_time", "end_time"],
            },
        ),
        Tool(
            name="get_gcp_audit_log_by_insert_id",
            description="Retrieve a specific GCP Audit Log entry by insert ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "insert_id": {"type": "string"},
                },
                "required": ["project_id", "insert_id"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    client = gcp_logging.Client(project=arguments.get("project_id"))

    if name == "get_gcp_audit_logs":
        filter_parts = [
            f'timestamp>="{arguments["start_time"]}"',
            f'timestamp<="{arguments["end_time"]}"',
            'logName:"cloudaudit.googleapis.com"',
        ]
        if arguments.get("log_filter"):
            filter_parts.append(arguments["log_filter"])
        filter_str = " AND ".join(filter_parts)
        entries = list(
            client.list_entries(
                filter_=filter_str,
                max_results=arguments.get("max_results", 50),
            )
        )
        return [TextContent(type="text", text=json.dumps([e.to_api_repr() for e in entries]))]

    if name == "get_gcp_audit_log_by_insert_id":
        filter_str = f'insertId="{arguments["insert_id"]}"'
        entries = list(client.list_entries(filter_=filter_str, max_results=1))
        result = entries[0].to_api_repr() if entries else {}
        return [TextContent(type="text", text=json.dumps(result))]

    return [TextContent(type="text", text=f"unknown tool: {name}")]


async def main() -> None:
    async with stdio_server() as streams:
        await app.run(*streams, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
