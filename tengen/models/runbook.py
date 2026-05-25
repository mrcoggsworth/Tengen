from pydantic import BaseModel


class RunbookStep(BaseModel):
    order: int
    name: str
    description: str
    tool: str
    parameters: dict = {}
    automated: bool = False


class Runbook(BaseModel):
    name: str
    event_type: str
    cloud_provider: str
    severity: str
    steps: list[RunbookStep]
    description: str = ""
