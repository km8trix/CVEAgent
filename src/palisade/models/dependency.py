"""Dependency and lockfile models. See IMPLEMENTATION_PLAN.md section 4.2."""

from typing import Literal

from pydantic import BaseModel, Field

from palisade.models.advisory import Ecosystem


class Dependency(BaseModel):
    ecosystem: Ecosystem
    name: str
    version: str
    direct: bool
    depth: int = 0
    path: list[str] = Field(default_factory=list)
    source_file: str

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


class DependencyGraph(BaseModel):
    target: str
    ecosystem: Ecosystem
    dependencies: list[Dependency]
    edges: list[tuple[str, str]] = Field(default_factory=list)


class Lockfile(BaseModel):
    path: str
    kind: Literal["package-lock", "pnpm-lock", "requirements", "poetry-lock"]
    raw: str
