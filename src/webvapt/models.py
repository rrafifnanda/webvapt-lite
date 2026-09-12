from typing import Literal

from pydantic import BaseModel


class Finding(BaseModel):
    check: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    url: str
    evidence: str = ""
    remediation: str = ""
