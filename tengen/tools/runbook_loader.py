from pathlib import Path

import yaml

from ..models.runbook import Runbook, RunbookStep

RUNBOOKS_DIR = Path(__file__).parent.parent.parent / "runbooks"


def load_runbook(cloud_provider: str, event_type: str) -> Runbook | None:
    provider_dir = RUNBOOKS_DIR / cloud_provider
    if not provider_dir.exists():
        return None
    slug = event_type.lower().replace(" ", "_")
    runbook_path = provider_dir / f"{slug}.yaml"
    if not runbook_path.exists():
        return None
    with open(runbook_path) as f:
        data = yaml.safe_load(f)
    steps = [RunbookStep(**step) for step in data.get("steps", [])]
    return Runbook(**{**data, "steps": steps})


def list_runbooks(cloud_provider: str) -> list[str]:
    provider_dir = RUNBOOKS_DIR / cloud_provider
    if not provider_dir.exists():
        return []
    return [p.stem for p in provider_dir.glob("*.yaml")]
