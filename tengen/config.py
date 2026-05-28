import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    # ── LLM ───────────────────────────────────────────────────────────────────
    google_api_key: str = field(default_factory=lambda: os.getenv("GOOGLE_API_KEY", ""))
    model_name: str = field(default_factory=lambda: os.getenv("MODEL_NAME", "gemini-2.0-flash"))

    # ── AWS ───────────────────────────────────────────────────────────────────
    aws_region: str = field(default_factory=lambda: os.getenv("AWS_REGION", "us-east-1"))
    aws_endpoint_url: str = field(default_factory=lambda: os.getenv("AWS_ENDPOINT_URL", ""))
    sqs_queue_url: str = field(default_factory=lambda: os.getenv("SQS_QUEUE_URL", ""))

    # ── GCP ───────────────────────────────────────────────────────────────────
    gcp_project_id: str = field(default_factory=lambda: os.getenv("GCP_PROJECT_ID", ""))
    pubsub_project_id: str = field(default_factory=lambda: os.getenv("PUBSUB_PROJECT_ID", ""))
    pubsub_subscription_id: str = field(default_factory=lambda: os.getenv("PUBSUB_SUBSCRIPTION_ID", ""))
    pubsub_emulator_host: str = field(default_factory=lambda: os.getenv("PUBSUB_EMULATOR_HOST", ""))

    # ── Azure ─────────────────────────────────────────────────────────────────
    azure_tenant_id: str = field(default_factory=lambda: os.getenv("AZURE_TENANT_ID", ""))
    azure_client_id: str = field(default_factory=lambda: os.getenv("AZURE_CLIENT_ID", ""))
    azure_client_secret: str = field(default_factory=lambda: os.getenv("AZURE_CLIENT_SECRET", ""))
    azure_subscription_id: str = field(default_factory=lambda: os.getenv("AZURE_SUBSCRIPTION_ID", ""))

    # ── CrowdStrike ───────────────────────────────────────────────────────────
    crowdstrike_client_id: str = field(default_factory=lambda: os.getenv("CROWDSTRIKE_CLIENT_ID", ""))
    crowdstrike_client_secret: str = field(default_factory=lambda: os.getenv("CROWDSTRIKE_CLIENT_SECRET", ""))
    crowdstrike_base_url: str = field(default_factory=lambda: os.getenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com"))

    # ── Kubernetes ────────────────────────────────────────────────────────────
    k8s_kubeconfig: str = field(default_factory=lambda: os.getenv("K8S_KUBECONFIG", ""))

    # ── Kafka ─────────────────────────────────────────────────────────────────
    kafka_bootstrap_servers: str = field(default_factory=lambda: os.getenv("KAFKA_BOOTSTRAP_SERVERS", ""))
    kafka_group_id: str = field(default_factory=lambda: os.getenv("KAFKA_GROUP_ID", "tengen"))
    kafka_topics: str = field(default_factory=lambda: os.getenv("KAFKA_TOPICS", "security-events"))

    # ── RabbitMQ ──────────────────────────────────────────────────────────────
    rabbitmq_url: str = field(default_factory=lambda: os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/"))

    # ── Splunk HEC ────────────────────────────────────────────────────────────
    splunk_hec_url: str = field(default_factory=lambda: os.getenv("SPLUNK_HEC_URL", ""))
    splunk_hec_token: str = field(default_factory=lambda: os.getenv("SPLUNK_HEC_TOKEN", ""))
    splunk_index: str = field(default_factory=lambda: os.getenv("SPLUNK_INDEX", "tengen"))
    splunk_batch_size: int = field(default_factory=lambda: int(os.getenv("SPLUNK_BATCH_SIZE", "25")))
    splunk_es_host: str = field(default_factory=lambda: os.getenv("SPLUNK_ES_HOST", ""))
    splunk_es_port: int = field(default_factory=lambda: int(os.getenv("SPLUNK_ES_PORT", "8089")))
    splunk_es_token: str = field(default_factory=lambda: os.getenv("SPLUNK_ES_TOKEN", ""))
    splunk_es_search: str = field(default_factory=lambda: os.getenv("SPLUNK_ES_SEARCH", "| search index=notable"))

    # ── Dashboard ─────────────────────────────────────────────────────────────
    dashboard_host: str = field(default_factory=lambda: os.getenv("DASHBOARD_HOST", "0.0.0.0"))
    dashboard_port: int = field(default_factory=lambda: int(os.getenv("DASHBOARD_PORT", "8080")))
    rabbitmq_mgmt_url: str = field(default_factory=lambda: os.getenv("RABBITMQ_MGMT_URL", "http://localhost:15672"))
    rabbitmq_user: str = field(default_factory=lambda: os.getenv("RABBITMQ_USER", "guest"))
    rabbitmq_pass: str = field(default_factory=lambda: os.getenv("RABBITMQ_PASS", "guest"))

    # ── Universal HTTP Consumer ────────────────────────────────────────────────
    universal_http_host: str = field(default_factory=lambda: os.getenv("UNIVERSAL_HTTP_HOST", "0.0.0.0"))
    universal_http_port: int = field(default_factory=lambda: int(os.getenv("UNIVERSAL_HTTP_PORT", "8088")))
    universal_http_token: str = field(default_factory=lambda: os.getenv("UNIVERSAL_HTTP_TOKEN", ""))

    # ── External Enrichment ───────────────────────────────────────────────────
    abuse_ipdb_key: str = field(default_factory=lambda: os.getenv("ABUSE_IPDB_KEY", ""))
    vt_api_key: str = field(default_factory=lambda: os.getenv("VT_API_KEY", ""))
    ipinfo_token: str = field(default_factory=lambda: os.getenv("IPINFO_TOKEN", ""))
    securitytrails_api_key: str = field(default_factory=lambda: os.getenv("SECURITYTRAILS_API_KEY", ""))
    okta_api_token: str = field(default_factory=lambda: os.getenv("OKTA_API_TOKEN", ""))
    okta_domain: str = field(default_factory=lambda: os.getenv("OKTA_DOMAIN", ""))
    cmdb_endpoint: str = field(default_factory=lambda: os.getenv("CMDB_ENDPOINT", ""))
    cmdb_token: str = field(default_factory=lambda: os.getenv("CMDB_TOKEN", ""))

    # ── PagerDuty ─────────────────────────────────────────────────────────────
    pagerduty_api_key: str = field(default_factory=lambda: os.getenv("PAGERDUTY_API_KEY", ""))

    # ── Legacy ────────────────────────────────────────────────────────────────
    siem_endpoint: str = field(default_factory=lambda: os.getenv("SIEM_ENDPOINT", ""))


settings = Settings()
