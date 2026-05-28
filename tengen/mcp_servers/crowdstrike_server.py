"""MCP stdio server for CrowdStrike Falcon detection retrieval."""
from __future__ import annotations

import asyncio
import json
import os

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("tengen-crowdstrike")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="get_cs_detections",
            description="Retrieve CrowdStrike detections for a time range",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_time": {"type": "string", "description": "ISO 8601 start time"},
                    "end_time": {"type": "string", "description": "ISO 8601 end time"},
                    "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Informational"]},
                    "max_results": {"type": "integer", "default": 50},
                },
                "required": ["start_time", "end_time"],
            },
        ),
        Tool(
            name="get_cs_detection_by_id",
            description="Retrieve a specific CrowdStrike detection by ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "detection_id": {"type": "string"},
                },
                "required": ["detection_id"],
            },
        ),
        Tool(
            name="get_cs_events",
            description="Query CrowdStrike Event Stream for raw events",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_type": {"type": "string", "description": "Optional event type filter"},
                    "start_time": {"type": "string"},
                    "end_time": {"type": "string"},
                    "max_results": {"type": "integer", "default": 100},
                },
            },
        ),
        Tool(
            name="get_cs_incidents",
            description="Retrieve CrowdStrike incidents",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_time": {"type": "string"},
                    "end_time": {"type": "string"},
                    "state": {"type": "string", "enum": ["open", "closed"]},
                    "max_results": {"type": "integer", "default": 50},
                },
                "required": ["start_time", "end_time"],
            },
        ),
    ]


def _get_token() -> str:
    """Obtain OAuth2 bearer token from CrowdStrike Falcon API."""
    import httpx
    base_url = os.environ.get("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")
    resp = httpx.post(
        f"{base_url}/oauth2/token",
        data={
            "client_id": os.environ["CROWDSTRIKE_CLIENT_ID"],
            "client_secret": os.environ["CROWDSTRIKE_CLIENT_SECRET"],
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    import httpx
    base_url = os.environ.get("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")
    token = _get_token()
    headers = {"Authorization": f"Bearer {token}"}

    if name == "get_cs_detections":
        fql_parts = [
            f"created_timestamp:>'{arguments['start_time']}'",
            f"created_timestamp:<'{arguments['end_time']}'",
        ]
        if arguments.get("severity"):
            fql_parts.append(f"max_severity_displayname:'{arguments['severity']}'")
        fql = "+".join(fql_parts)
        ids_resp = httpx.get(
            f"{base_url}/detects/queries/detects/v1",
            params={"filter": fql, "limit": arguments.get("max_results", 50)},
            headers=headers,
            timeout=15,
        )
        ids_resp.raise_for_status()
        ids = ids_resp.json().get("resources", [])
        if not ids:
            return [TextContent(type="text", text="[]")]
        detail_resp = httpx.post(
            f"{base_url}/detects/entities/summaries/GET/v1",
            json={"ids": ids},
            headers=headers,
            timeout=15,
        )
        detail_resp.raise_for_status()
        return [TextContent(type="text", text=json.dumps(detail_resp.json().get("resources", [])))]

    if name == "get_cs_detection_by_id":
        resp = httpx.post(
            f"{base_url}/detects/entities/summaries/GET/v1",
            json={"ids": [arguments["detection_id"]]},
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        resources = resp.json().get("resources", [])
        return [TextContent(type="text", text=json.dumps(resources[0] if resources else {}))]

    if name == "get_cs_events":
        params: dict = {"limit": arguments.get("max_results", 100)}
        if arguments.get("event_type"):
            params["event_type"] = arguments["event_type"]
        if arguments.get("start_time"):
            params["start"] = arguments["start_time"]
        if arguments.get("end_time"):
            params["stop"] = arguments["end_time"]
        resp = httpx.get(
            f"{base_url}/fwmgr/queries/events/v1",
            params=params,
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        return [TextContent(type="text", text=json.dumps(resp.json()))]

    if name == "get_cs_incidents":
        fql_parts = [
            f"start:>'{arguments['start_time']}'",
            f"start:<'{arguments['end_time']}'",
        ]
        if arguments.get("state"):
            fql_parts.append(f"state:'{arguments['state']}'")
        ids_resp = httpx.get(
            f"{base_url}/incidents/queries/incidents/v1",
            params={"filter": "+".join(fql_parts), "limit": arguments.get("max_results", 50)},
            headers=headers,
            timeout=15,
        )
        ids_resp.raise_for_status()
        ids = ids_resp.json().get("resources", [])
        if not ids:
            return [TextContent(type="text", text="[]")]
        detail_resp = httpx.post(
            f"{base_url}/incidents/entities/incidents/GET/v1",
            json={"ids": ids},
            headers=headers,
            timeout=15,
        )
        detail_resp.raise_for_status()
        return [TextContent(type="text", text=json.dumps(detail_resp.json().get("resources", [])))]

    return [TextContent(type="text", text=f"unknown tool: {name}")]


async def main() -> None:
    async with stdio_server() as streams:
        await app.run(*streams, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
