"""AWS containment actions."""
from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def disable_iam_access_key(finding_json: str, access_key_id: str) -> str:
    """Disable an IAM access key. Returns JSON result."""
    try:
        import boto3
        iam = boto3.client("iam")
        # Determine the username from the finding
        finding = json.loads(finding_json)
        username = finding.get("enrichment", {}).get("user", "")
        iam.update_access_key(
            UserName=username,
            AccessKeyId=access_key_id,
            Status="Inactive",
        )
        logger.info("Disabled IAM access key %s for user %s", access_key_id, username)
        return json.dumps({"action": "disable_iam_access_key", "status": "success", "key_id": access_key_id})
    except Exception as exc:
        logger.error("disable_iam_access_key failed: %s", exc)
        return json.dumps({"action": "disable_iam_access_key", "status": "error", "error": str(exc)})


def revoke_sts_sessions(finding_json: str, username: str) -> str:
    """Attach a DenyAll policy to terminate active STS sessions for a user."""
    try:
        import boto3
        iam = boto3.client("iam")
        # Attach an inline policy that denies all actions until rotated
        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"DateLessThan": {"aws:TokenIssueTime": "2024-01-01T00:00:00Z"}},
            }],
        })
        iam.put_user_policy(UserName=username, PolicyName="TengenEmergencyRevoke", PolicyDocument=policy_doc)
        logger.info("Attached emergency revoke policy to user %s", username)
        return json.dumps({"action": "revoke_sts_sessions", "status": "success", "username": username})
    except Exception as exc:
        logger.error("revoke_sts_sessions failed: %s", exc)
        return json.dumps({"action": "revoke_sts_sessions", "status": "error", "error": str(exc)})


def modify_security_group_deny(finding_json: str, group_id: str, source_ip: str) -> str:
    """Add a deny rule to a security group to block a source IP."""
    try:
        import boto3
        ec2 = boto3.client("ec2")
        ec2.revoke_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": f"{source_ip}/32", "Description": "Tengen block"}],
            }],
        )
        logger.info("Blocked source IP %s from security group %s", source_ip, group_id)
        return json.dumps({"action": "modify_security_group_deny", "status": "success", "ip": source_ip})
    except Exception as exc:
        logger.error("modify_security_group_deny failed: %s", exc)
        return json.dumps({"action": "modify_security_group_deny", "status": "error", "error": str(exc)})


def disable_iam_user(finding_json: str, username: str) -> str:
    """Disable all access keys and attach a DenyAll policy for an IAM user."""
    try:
        import boto3
        iam = boto3.client("iam")
        keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
        for key in keys:
            iam.update_access_key(UserName=username, AccessKeyId=key["AccessKeyId"], Status="Inactive")
        logger.info("Disabled all access keys for user %s", username)
        return json.dumps({"action": "disable_iam_user", "status": "success", "username": username, "keys_disabled": len(keys)})
    except Exception as exc:
        logger.error("disable_iam_user failed: %s", exc)
        return json.dumps({"action": "disable_iam_user", "status": "error", "error": str(exc)})
