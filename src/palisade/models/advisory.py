"""Normalized advisory record (OSV-shaped). See IMPLEMENTATION_PLAN.md section 4.1."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Ecosystem = Literal["npm", "PyPI"]
SeverityBucket = Literal["low", "medium", "high", "critical"]


class Event(BaseModel):
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None


class Range(BaseModel):
    type: Literal["SEMVER", "ECOSYSTEM", "GIT"]
    events: list[Event]


class AffectedPackage(BaseModel):
    ecosystem: Ecosystem
    name: str
    ranges: list[Range] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)
    database_specific: dict[str, Any] = Field(default_factory=dict)


class Severity(BaseModel):
    cvss_vector: str | None = None
    cvss_score: float | None = None
    bucket: SeverityBucket | None = None


class AdvisoryRecord(BaseModel):
    id: str
    source: Literal["osv", "nvd", "ghsa"]
    source_id: str
    aliases: list[str] = Field(default_factory=list)
    summary: str
    details: str
    severity: Severity
    cwe_ids: list[str] = Field(default_factory=list)
    affected: list[AffectedPackage]
    references: list[str] = Field(default_factory=list)
    published: datetime
    modified: datetime
    content_hash: str
