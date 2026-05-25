import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    google_api_key: str = field(default_factory=lambda: os.getenv("GOOGLE_API_KEY", ""))
    aws_region: str = field(default_factory=lambda: os.getenv("AWS_REGION", "us-east-1"))
    gcp_project_id: str = field(default_factory=lambda: os.getenv("GCP_PROJECT_ID", ""))
    siem_endpoint: str = field(default_factory=lambda: os.getenv("SIEM_ENDPOINT", ""))
    pagerduty_api_key: str = field(default_factory=lambda: os.getenv("PAGERDUTY_API_KEY", ""))
    model_name: str = field(default_factory=lambda: os.getenv("MODEL_NAME", "gemini-2.0-flash"))


settings = Settings()
