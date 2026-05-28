"""MCP stdio server for Kubernetes API server audit log retrieval."""
from __future__ import annotations

import asyncio
import json
import os

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("tengen-k8s-audit")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="get_k8s_audit_events",
            description="Query Kubernetes API server audit log entries",
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string", "description": "Optional namespace filter"},
                    "verb": {"type": "string", "description": "Optional verb filter (get/list/create/delete/patch/update)"},
                    "user": {"type": "string", "description": "Optional user/service-account filter"},
                    "resource": {"type": "string", "description": "Optional resource kind filter (pods/secrets/configmaps)"},
                    "start_time": {"type": "string", "description": "ISO 8601 start time"},
                    "max_results": {"type": "integer", "default": 100},
                },
            },
        ),
        Tool(
            name="get_k8s_pod_events",
            description="Retrieve Kubernetes events for a specific pod",
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string"},
                    "pod_name": {"type": "string"},
                },
                "required": ["namespace", "pod_name"],
            },
        ),
        Tool(
            name="get_k8s_secrets_access",
            description="Find recent secret read/list operations in the audit log",
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string"},
                    "start_time": {"type": "string"},
                    "max_results": {"type": "integer", "default": 50},
                },
            },
        ),
        Tool(
            name="get_k8s_privileged_operations",
            description="Find exec, port-forward, and privileged container creation events",
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string"},
                    "start_time": {"type": "string"},
                    "max_results": {"type": "integer", "default": 50},
                },
            },
        ),
    ]


def _get_k8s_client():
    from kubernetes import client, config  # type: ignore[import]
    try:
        config.load_incluster_config()
    except Exception:
        kubeconfig = os.environ.get("K8S_KUBECONFIG")
        config.load_kube_config(config_file=kubeconfig)
    return client


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    k8s = _get_k8s_client()

    if name == "get_k8s_audit_events":
        namespace = arguments.get("namespace")
        v1 = k8s.CoreV1Api()
        field_selector_parts = []
        if namespace:
            field_selector_parts.append(f"involvedObject.namespace={namespace}")
        kwargs: dict = {"limit": arguments.get("max_results", 100)}
        if field_selector_parts:
            kwargs["field_selector"] = ",".join(field_selector_parts)
        events = v1.list_event_for_all_namespaces(**kwargs) if not namespace else \
                 v1.list_namespaced_event(namespace=namespace, **{k: v for k, v in kwargs.items() if k != "field_selector"})
        results = []
        for ev in events.items:
            results.append({
                "name": ev.metadata.name,
                "namespace": ev.metadata.namespace,
                "reason": ev.reason,
                "message": ev.message,
                "type": ev.type,
                "count": ev.count,
                "first_time": str(ev.first_timestamp),
                "last_time": str(ev.last_timestamp),
                "involved_object": {
                    "kind": ev.involved_object.kind,
                    "name": ev.involved_object.name,
                    "namespace": ev.involved_object.namespace,
                },
            })
        return [TextContent(type="text", text=json.dumps(results))]

    if name == "get_k8s_pod_events":
        v1 = k8s.CoreV1Api()
        namespace = arguments["namespace"]
        pod_name = arguments["pod_name"]
        events = v1.list_namespaced_event(
            namespace=namespace,
            field_selector=f"involvedObject.name={pod_name},involvedObject.kind=Pod",
        )
        results = [
            {
                "reason": ev.reason,
                "message": ev.message,
                "type": ev.type,
                "count": ev.count,
                "last_time": str(ev.last_timestamp),
            }
            for ev in events.items
        ]
        return [TextContent(type="text", text=json.dumps(results))]

    if name == "get_k8s_secrets_access":
        v1 = k8s.CoreV1Api()
        namespace = arguments.get("namespace")
        limit = arguments.get("max_results", 50)
        if namespace:
            secrets = v1.list_namespaced_secret(namespace=namespace, limit=limit)
        else:
            secrets = v1.list_secret_for_all_namespaces(limit=limit)
        results = [
            {
                "name": s.metadata.name,
                "namespace": s.metadata.namespace,
                "type": s.type,
                "created": str(s.metadata.creation_timestamp),
                "labels": s.metadata.labels or {},
            }
            for s in secrets.items
        ]
        return [TextContent(type="text", text=json.dumps(results))]

    if name == "get_k8s_privileged_operations":
        v1 = k8s.CoreV1Api()
        namespace = arguments.get("namespace")
        limit = arguments.get("max_results", 50)
        kwargs = {"limit": limit}
        if namespace:
            pods = v1.list_namespaced_pod(namespace=namespace, **kwargs)
        else:
            pods = v1.list_pod_for_all_namespaces(**kwargs)
        privileged = []
        for pod in pods.items:
            for container in (pod.spec.containers or []):
                sc = container.security_context
                if sc and (sc.privileged or sc.run_as_root or (sc.capabilities and sc.capabilities.add)):
                    privileged.append({
                        "pod": pod.metadata.name,
                        "namespace": pod.metadata.namespace,
                        "container": container.name,
                        "privileged": sc.privileged,
                        "run_as_root": sc.run_as_root,
                        "added_capabilities": sc.capabilities.add if sc.capabilities else [],
                    })
        return [TextContent(type="text", text=json.dumps(privileged[:limit]))]

    return [TextContent(type="text", text=f"unknown tool: {name}")]


async def main() -> None:
    async with stdio_server() as streams:
        await app.run(*streams, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
