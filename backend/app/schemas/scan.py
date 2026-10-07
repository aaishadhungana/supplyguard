from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.models.scan import ScanStatus


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    number: int
    status: ScanStatus
    source_filename: str | None
    warnings: list[str]
    risk_score: float | None
    ai_status: str | None
    ai_message: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None