from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

Criticality = Literal["low", "medium", "high", "critical"]


class ProjectCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    internet_facing: bool = False
    criticality: Criticality = "medium"


class ProjectContextUpdate(BaseModel):
    internet_facing: bool | None = None
    criticality: Criticality | None = None


class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None
    internet_facing: bool
    criticality: str
    created_at: datetime