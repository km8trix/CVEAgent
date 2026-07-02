"""Synchronous scan endpoint (M1). Async queue mode arrives in M3."""

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from palisade.models.finding import ScanReport
from palisade.scanner import scan_content

router = APIRouter(tags=["scan"])

_MAX_CONTENT = 500_000  # 500 KB — generous for any real lockfile


class ScanRequest(BaseModel):
    filename: str  # e.g. "requirements.txt" — used to pick the parser
    content: str

    @field_validator("content")
    @classmethod
    def _limit_size(cls, value: str) -> str:
        if len(value) > _MAX_CONTENT:
            raise ValueError("lockfile content exceeds 500 KB limit")
        return value


@router.post("/scan", response_model=ScanReport)
async def scan(req: ScanRequest) -> ScanReport:
    try:
        return await scan_content(req.filename, req.content)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail="OSV upstream error") from exc
    except httpx.TransportError as exc:
        raise HTTPException(status_code=503, detail="OSV upstream unreachable") from exc
