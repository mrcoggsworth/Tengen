"""MCP stdio server for Azure Activity Log retrieval."""
from __future__ import annotations

import asyncio
import json
import os

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("tengen-azure-activity")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="get_azure_activity_logs",
            description="Retrieve Azure Activity Log entries for a subscription within a time window",
            inputSchema={
                "type": "object",
                "properties": {
                    "subscription_id": {"type": "string", "description": "Azure subscription ID"},
                    "start_time": {"type": "string", "description": "ISO 8601 start time"},
                    "end_time": {"type": "string", "description": "ISO 8601 end time"},
                    "resource_group": {"type": "string", "description": "Optional resource group filter"},
                    "caller": {"type": "string", "description": "Optional caller UPN/app filter"},
                    "max_results": {"type": "integer", "default": 50},
                },
                "required": ["subscription_id", "start_time", "end_time"],
            },
        ),
        Tool(
            name="get_azure_activity_log_by_correlation_id",
            description="Retrieve Azure Activity Log entries matching a correlation ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "subscription_id": {"type": "string"},
                    "correlation_id": {"type": "string"},
                },
                "required": ["subscription_id", "correlation_id"],
            },
        ),
        Tool(
            name="get_azure_signin_logs",
            description="Retrieve Azure AD sign-in logs for a user or time range",
            inputSchema={
                "type": "object",
                "properties": {
                    "user_principal_name": {"type": "string", "description": "Optional UPN filter"},
                    "start_time": {"type": "string"},
                    "end_time": {"type": "string"},
                    "max_results": {"type": "integer", "default": 50},
                },
                "required": ["start_time", "end_time"],
            },
        ),
    ]


def _get_token() -> str:
    import httpx
    tenant_id = os.environ["AZURE_TENANT_ID"]
    client_id = os.environ["AZURE_CLIENT_ID"]
    client_secret = os.environ["AZURE_CLIENT_SECRET"]
    resp = httpx.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://management.azure.com/.default",
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _get_graph_token() -> str:
    import httpx
    tenant_id = os.environ["AZURE_TENANT_ID"]
    client_id = os.environ["AZURE_CLIENT_ID"]
    client_secret = os.environ["AZURE_CLIENT_SECRET"]
    resp = httpx.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    import httpx

    if name == "get_azure_activity_logs":
        token = _get_token()
        sub = arguments["subscription_id"]
        filter_parts = [
            f"eventTimestamp ge '{arguments['start_time']}'",
            f"eventTimestamp le '{arguments['end_time']}'",
        ]
        if arguments.get("resource_group"):
            filter_parts.append(f"resourceGroupName eq '{arguments['resource_group']}'")
        if arguments.get("caller"):
            filter_parts.append(f"caller eq '{arguments['caller']}'")
        filter_str = " and ".join(filter_parts)
        resp = httpx.get(
            f"https://management.azure.com/subscriptions/{sub}/providers/microsoft.insights/eventtypes/management/values",
            params={"api-version": "2015-04-01", "$filter": filter_str,
                    "$top": arguments.get("max_results", 50)},
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        resp.raise_for_status()
        events = resp.json().get("value", [])
        return [TextContent(type="text", text=json.dumps(events))]

    if name == "get_azure_activity_log_by_correlation_id":
        token = _get_token()
        sub = arguments["subscription_id"]
        cid = arguments["correlation_id"]
        filter_str = f"correlationId eq '{cid}'"
        resp = httpx.get(
            f"https://management.azure.com/subscriptions/{sub}/providers/microsoft.insights/eventtypes/management/values",
            params={"api-version": "2015-04-01", "$filter": filter_str},
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        resp.raise_for_status()
        return [TextContent(type="text", text=json.dumps(resp.json().get("value", [])))]

    if name == "get_azure_signin_logs":
        token = _get_graph_token()
        params: dict = {"$top": arguments.get("max_results", 50)}
        filters = [
            f"createdDateTime ge {arguments['start_time']}",
            f"createdDateTime le {arguments['end_time']}",
        ]
        if arguments.get("user_principal_name"):
            filters.append(f"userPrincipalName eq '{arguments['user_principal_name']}'")
        params["$filter"] = " and ".join(filters)
        resp = httpx.get(
            "https://graph.microsoft.com/v1.0/auditLogs/signIns",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        resp.raise_for_status()
        return [TextContent(type="text", text=json.dumps(resp.json().get("value", [])))]

    return [TextContent(type="text", text=f"unknown tool: {name}")]


async def main() -> None:
    async with stdio_server() as streams:
        await app.run(*streams, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
