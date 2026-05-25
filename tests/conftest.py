import pytest


@pytest.fixture
def sample_cloudtrail_event():
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "accountId": "123456789012",
            "arn": "arn:aws:iam::123456789012:user/alice",
        },
        "eventTime": "2024-01-15T10:30:00Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.10",
        "userAgent": "aws-cli/2.0",
        "errorCode": "AccessDenied",
        "errorMessage": "User is not authorized to perform sts:AssumeRole",
        "requestParameters": {"roleArn": "arn:aws:iam::999999999999:role/AdminRole"},
    }


@pytest.fixture
def sample_gcp_audit_event():
    return {
        "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
        "severity": "WARNING",
        "timestamp": "2024-01-15T10:30:00Z",
        "resource": {
            "type": "gcs_bucket",
            "labels": {"project_id": "my-project", "bucket_name": "sensitive-data"},
        },
        "protoPayload": {
            "serviceName": "storage.googleapis.com",
            "methodName": "storage.buckets.setIamPolicy",
            "resourceName": "projects/_/buckets/sensitive-data",
            "authenticationInfo": {"principalEmail": "user@example.com"},
            "requestMetadata": {
                "callerIp": "198.51.100.5",
                "callerSuppliedUserAgent": "gsutil/5.0",
            },
            "authorizationInfo": [
                {"granted": True, "permission": "storage.buckets.setIamPolicy"}
            ],
        },
    }
