from ..models.alert import Alert


def enrich_cloudtrail_alert(alert: Alert) -> dict:
    event = alert.raw_event
    return {
        "user_agent": event.get("userAgent", ""),
        "source_ip": event.get("sourceIPAddress", ""),
        "user_identity_type": event.get("userIdentity", {}).get("type", ""),
        "user_arn": event.get("userIdentity", {}).get("arn", ""),
        "error_code": event.get("errorCode", ""),
        "error_message": event.get("errorMessage", ""),
        "request_parameters": event.get("requestParameters", {}),
    }


def enrich_gcp_audit_alert(alert: Alert) -> dict:
    payload = alert.raw_event.get("protoPayload", {})
    return {
        "caller_ip": payload.get("requestMetadata", {}).get("callerIp", ""),
        "caller_user_agent": payload.get("requestMetadata", {}).get("callerSuppliedUserAgent", ""),
        "principal_email": payload.get("authenticationInfo", {}).get("principalEmail", ""),
        "service_name": payload.get("serviceName", ""),
        "resource_name": payload.get("resourceName", ""),
        "authorization_info": payload.get("authorizationInfo", []),
    }
