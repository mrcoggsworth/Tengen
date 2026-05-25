"""MCP stdio server for AWS CloudTrail log retrieval."""
import asyncio
import json

import boto3
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("tengen-cloudtrail")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="get_cloudtrail_events",
            description="Retrieve recent CloudTrail events for a given time window",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_time": {"type": "string", "description": "ISO 8601 start time"},
                    "end_time": {"type": "string", "description": "ISO 8601 end time"},
                    "event_name": {"type": "string", "description": "Optional event name filter"},
                    "max_results": {"type": "integer", "default": 50},
                },
                "required": ["start_time", "end_time"],
            },
        ),
        Tool(
            name="get_cloudtrail_event_by_id",
            description="Retrieve a specific CloudTrail event by event ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_id": {"type": "string"},
                },
                "required": ["event_id"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    client = boto3.client("cloudtrail")
    if name == "get_cloudtrail_events":
        kwargs: dict = {
            "StartTime": arguments["start_time"],
            "EndTime": arguments["end_time"],
            "MaxResults": arguments.get("max_results", 50),
        }
        if "event_name" in arguments:
            kwargs["LookupAttributes"] = [
                {"AttributeKey": "EventName", "AttributeValue": arguments["event_name"]}
            ]
        resp = client.lookup_events(**kwargs)
        return [TextContent(type="text", text=json.dumps(resp.get("Events", [])))]

    if name == "get_cloudtrail_event_by_id":
        resp = client.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "EventId", "AttributeValue": arguments["event_id"]}
            ]
        )
        events = resp.get("Events", [])
        return [TextContent(type="text", text=json.dumps(events[0] if events else {}))]

    return [TextContent(type="text", text=f"unknown tool: {name}")]


async def main() -> None:
    async with stdio_server() as streams:
        await app.run(*streams, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
