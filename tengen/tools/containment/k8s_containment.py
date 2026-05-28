"""Kubernetes containment actions."""
from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)


def cordon_node(finding_json: str, node_name: str) -> str:
    try:
        from kubernetes import client, config  # type: ignore[import]
        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        v1 = client.CoreV1Api()
        body = {"spec": {"unschedulable": True}}
        v1.patch_node(node_name, body)
        logger.info("Cordoned K8s node %s", node_name)
        return json.dumps({"action": "cordon_node", "status": "success", "node": node_name})
    except Exception as exc:
        logger.error("cordon_node failed: %s", exc)
        return json.dumps({"action": "cordon_node", "status": "error", "error": str(exc)})


def delete_pod(finding_json: str, namespace: str, pod_name: str) -> str:
    try:
        from kubernetes import client, config  # type: ignore[import]
        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        v1 = client.CoreV1Api()
        v1.delete_namespaced_pod(name=pod_name, namespace=namespace)
        logger.info("Deleted pod %s/%s", namespace, pod_name)
        return json.dumps({"action": "delete_pod", "status": "success", "namespace": namespace, "pod": pod_name})
    except Exception as exc:
        logger.error("delete_pod failed: %s", exc)
        return json.dumps({"action": "delete_pod", "status": "error", "error": str(exc)})


def delete_service_account_token(finding_json: str, namespace: str, secret_name: str) -> str:
    try:
        from kubernetes import client, config  # type: ignore[import]
        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        v1 = client.CoreV1Api()
        v1.delete_namespaced_secret(name=secret_name, namespace=namespace)
        logger.info("Deleted SA token secret %s/%s", namespace, secret_name)
        return json.dumps({"action": "delete_service_account_token", "status": "success", "secret": secret_name})
    except Exception as exc:
        logger.error("delete_service_account_token failed: %s", exc)
        return json.dumps({"action": "delete_service_account_token", "status": "error", "error": str(exc)})


def create_network_policy_deny(finding_json: str, namespace: str, label_selector: dict) -> str:
    try:
        from kubernetes import client, config  # type: ignore[import]
        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        net_v1 = client.NetworkingV1Api()
        policy = client.V1NetworkPolicy(
            metadata=client.V1ObjectMeta(name="tengen-quarantine", namespace=namespace),
            spec=client.V1NetworkPolicySpec(
                pod_selector=client.V1LabelSelector(match_labels=label_selector),
                policy_types=["Ingress", "Egress"],
            ),
        )
        net_v1.create_namespaced_network_policy(namespace=namespace, body=policy)
        logger.info("Created deny NetworkPolicy in namespace %s", namespace)
        return json.dumps({"action": "create_network_policy_deny", "status": "success", "namespace": namespace})
    except Exception as exc:
        logger.error("create_network_policy_deny failed: %s", exc)
        return json.dumps({"action": "create_network_policy_deny", "status": "error", "error": str(exc)})
