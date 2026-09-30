from typing import Optional
from sqlmodel import SQLModel, Field


class ScanHistory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    url: str
    score: int
    risk_level: str
    findings: str