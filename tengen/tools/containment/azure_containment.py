"""Azure containment actions."""
from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger(__name__)


def disable_azure_ad_user(finding_json: str, user_id: str) -> str:
    try:
        import httpx
        token = _get_graph_token()
        resp = httpx.patch(
            f"https://graph.microsoft.com/v1.0/users/{user_id}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"accountEnabled": False},
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("Disabled Azure AD user %s", user_id)
        return json.dumps({"action": "disable_azure_ad_user", "status": "success", "user_id": user_id})
    except Exception as exc:
        logger.error("disable_azure_ad_user failed: %s", exc)
        return json.dumps({"action": "disable_azure_ad_user", "status": "error", "error": str(exc)})


def revoke_azure_refresh_tokens(finding_json: str, user_id: str) -> str:
    try:
        import httpx
        token = _get_graph_token()
        resp = httpx.post(
            f"https://graph.microsoft.com/v1.0/users/{user_id}/revokeSignInSessions",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("Revoked Azure refresh tokens for user %s", user_id)
        return json.dumps({"action": "revoke_azure_refresh_tokens", "status": "success", "user_id": user_id})
    except Exception as exc:
        logger.error("revoke_azure_refresh_tokens failed: %s", exc)
        return json.dumps({"action": "revoke_azure_refresh_tokens", "status": "error", "error": str(exc)})


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
