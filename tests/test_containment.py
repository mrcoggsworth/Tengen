"""Unit tests for containment tools (mocked cloud SDK calls)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


FINDING_JSON = json.dumps({
    "finding_id": "f-123",
    "severity": "CRITICAL",
    "enrichment": {"user": "alice"},
})


# ── AWS containment ───────────────────────────────────────────────────────────

class TestDisableIamAccessKey:
    def test_success(self):
        mock_iam = MagicMock()
        mock_iam.update_access_key.return_value = {}
        finding = json.dumps({"enrichment": {"user": "alice"}})
        with patch("boto3.client", return_value=mock_iam):
            from tengen.tools.containment.aws_containment import disable_iam_access_key
            result = json.loads(disable_iam_access_key(finding, "AKIAIOSFODNN7EXAMPLE"))
        assert result["status"] == "success"
        assert result["action"] == "disable_iam_access_key"
        mock_iam.update_access_key.assert_called_once_with(
            UserName="alice",
            AccessKeyId="AKIAIOSFODNN7EXAMPLE",
            Status="Inactive",
        )

    def test_error_handling(self):
        from botocore.exceptions import ClientError  # type: ignore[import]
        mock_iam = MagicMock()
        mock_iam.update_access_key.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "User not found"}}, "UpdateAccessKey"
        )
        with patch("boto3.client", return_value=mock_iam):
            from tengen.tools.containment.aws_containment import disable_iam_access_key
            result = json.loads(disable_iam_access_key(FINDING_JSON, "AKIAIOSFODNN7EXAMPLE"))
        assert result["status"] == "error"
        assert "error" in result


class TestRevokeStsSessions:
    def test_success(self):
        mock_iam = MagicMock()
        mock_iam.put_user_policy.return_value = {}
        with patch("boto3.client", return_value=mock_iam):
            from tengen.tools.containment.aws_containment import revoke_sts_sessions
            result = json.loads(revoke_sts_sessions(FINDING_JSON, "alice"))
        assert result["status"] == "success"
        assert result["username"] == "alice"
        mock_iam.put_user_policy.assert_called_once()

    def test_policy_document_structure(self):
        captured = {}
        def fake_put(UserName, PolicyName, PolicyDocument):
            captured["doc"] = json.loads(PolicyDocument)

        mock_iam = MagicMock()
        mock_iam.put_user_policy.side_effect = fake_put
        with patch("boto3.client", return_value=mock_iam):
            from tengen.tools.containment.aws_containment import revoke_sts_sessions
            revoke_sts_sessions(FINDING_JSON, "alice")
        assert captured["doc"]["Statement"][0]["Effect"] == "Deny"
        assert captured["doc"]["Statement"][0]["Action"] == "*"


class TestDisableIamUser:
    def test_disables_all_keys(self):
        mock_iam = MagicMock()
        mock_iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "KEY1"},
                {"AccessKeyId": "KEY2"},
            ]
        }
        with patch("boto3.client", return_value=mock_iam):
            from tengen.tools.containment.aws_containment import disable_iam_user
            result = json.loads(disable_iam_user(FINDING_JSON, "alice"))
        assert result["status"] == "success"
        assert result["keys_disabled"] == 2
        assert mock_iam.update_access_key.call_count == 2

    def test_no_keys(self):
        mock_iam = MagicMock()
        mock_iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
        with patch("boto3.client", return_value=mock_iam):
            from tengen.tools.containment.aws_containment import disable_iam_user
            result = json.loads(disable_iam_user(FINDING_JSON, "alice"))
        assert result["status"] == "success"
        assert result["keys_disabled"] == 0


# ── GCP containment ───────────────────────────────────────────────────────────

class TestDisableGcpServiceAccount:
    def test_success(self):
        mock_service = MagicMock()
        mock_service.projects.return_value.serviceAccounts.return_value.disable.return_value.execute.return_value = {}
        with patch("googleapiclient.discovery.build", return_value=mock_service):
            from tengen.tools.containment.gcp_containment import disable_service_account
            result = json.loads(disable_service_account(FINDING_JSON, "sa@project.iam.gserviceaccount.com", "my-project"))
        assert result["status"] == "success"
        assert result["sa"] == "sa@project.iam.gserviceaccount.com"


class TestAddVpcFirewallDeny:
    def test_success(self):
        mock_service = MagicMock()
        mock_service.firewalls.return_value.insert.return_value.execute.return_value = {}
        with patch("googleapiclient.discovery.build", return_value=mock_service):
            from tengen.tools.containment.gcp_containment import add_vpc_firewall_deny
            result = json.loads(add_vpc_firewall_deny(FINDING_JSON, "my-project", "1.2.3.4"))
        assert result["status"] == "success"
        assert result["ip"] == "1.2.3.4"

    def test_rule_name_replaces_dots(self):
        captured = {}
        mock_service = MagicMock()
        def fake_insert(project, body):
            captured["body"] = body
            return MagicMock()
        mock_service.firewalls.return_value.insert.side_effect = fake_insert
        mock_service.firewalls.return_value.insert.return_value.execute.return_value = {}
        with patch("googleapiclient.discovery.build", return_value=mock_service):
            from tengen.tools.containment.gcp_containment import add_vpc_firewall_deny
            add_vpc_firewall_deny(FINDING_JSON, "my-project", "1.2.3.4")
        assert "-" in captured.get("body", {}).get("name", "1.2.3.4")


# ── Azure containment ─────────────────────────────────────────────────────────

class TestDisableAzureAdUser:
    def test_success(self, monkeypatch):
        import os
        monkeypatch.setenv("AZURE_TENANT_ID", "tenant-1")
        monkeypatch.setenv("AZURE_CLIENT_ID", "client-1")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-1")

        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"access_token": "tok123"}

        with patch("httpx.post", return_value=mock_resp), \
             patch("httpx.patch", return_value=MagicMock(raise_for_status=lambda: None)):
            from tengen.tools.containment.azure_containment import disable_azure_ad_user
            result = json.loads(disable_azure_ad_user(FINDING_JSON, "user-id-123"))
        assert result["status"] == "success"
        assert result["user_id"] == "user-id-123"


# ── Kubernetes containment ────────────────────────────────────────────────────

class TestCordonNode:
    def test_success(self):
        mock_v1 = MagicMock()
        mock_v1.patch_node.return_value = MagicMock()
        with patch("kubernetes.client.CoreV1Api", return_value=mock_v1), \
             patch("kubernetes.config.load_incluster_config"), \
             patch("kubernetes.config.load_kube_config"):
            from tengen.tools.containment.k8s_containment import cordon_node
            result = json.loads(cordon_node(FINDING_JSON, "node-01"))
        assert result["status"] == "success"
        assert result["node"] == "node-01"


class TestDeletePod:
    def test_success(self):
        mock_v1 = MagicMock()
        mock_v1.delete_namespaced_pod.return_value = MagicMock()
        with patch("kubernetes.client.CoreV1Api", return_value=mock_v1), \
             patch("kubernetes.config.load_incluster_config"), \
             patch("kubernetes.config.load_kube_config"):
            from tengen.tools.containment.k8s_containment import delete_pod
            result = json.loads(delete_pod(FINDING_JSON, "production", "evil-pod"))
        assert result["status"] == "success"
        assert result["pod"] == "evil-pod"


class TestCreateNetworkPolicyDeny:
    def test_success(self):
        mock_net_v1 = MagicMock()
        mock_net_v1.create_namespaced_network_policy.return_value = MagicMock()
        with patch("kubernetes.client.NetworkingV1Api", return_value=mock_net_v1), \
             patch("kubernetes.config.load_incluster_config"), \
             patch("kubernetes.config.load_kube_config"):
            from tengen.tools.containment.k8s_containment import create_network_policy_deny
            result = json.loads(create_network_policy_deny(FINDING_JSON, "production", {"app": "evil"}))
        assert result["status"] == "success"
        assert result["namespace"] == "production"
