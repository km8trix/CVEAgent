"""Scan endpoints (M3 async queue).

POST /scan enqueues a scan and returns its id immediately (202); the worker runs
it out of band. GET /scans/{id} returns the full ScanReport once done, or a status
envelope while pending/running/errored.
"""

from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from palisade import queue
from palisade.db.base import get_session
from palisade.models.finding import ScanReport

router = APIRouter(tags=["scan"])

SessionDep = Annotated[Session, Depends(get_session)]

_MAX_CONTENT = 500_000  # 500 KB — generous for any real lockfile
ScanState = Literal["pending", "running", "done", "error"]


class ScanRequest(BaseModel):
    filename: str  # e.g. "requirements.txt" — used to pick the parser
    content: str
    engine: Literal["scan", "graph"] = "scan"  # M1 pipeline (default) or M2 agent graph

    @field_validator("content")
    @classmethod
    def _limit_size(cls, value: str) -> str:
        # Bound bytes, not characters — a multi-byte payload must not slip past the cap.
        if len(value.encode("utf-8")) > _MAX_CONTENT:
            raise ValueError("lockfile content exceeds 500 KB limit")
        return value


class ScanStatus(BaseModel):
    id: str
    status: ScanState
    error: str | None = None


@router.post("/scan", status_code=status.HTTP_202_ACCEPTED, response_model=ScanStatus)
def enqueue_scan(req: ScanRequest, session: SessionDep) -> ScanStatus:
    # ponytail: parse errors (bad filename/lockfile) surface in the worker as
    # status='error', not here — no pre-validation of the parser at enqueue time.
    scan_id = queue.enqueue(session, req.filename, req.content, req.engine)
    return ScanStatus(id=scan_id, status="pending")


# response_model=None: this returns two different shapes (full report vs status
# envelope); FastAPI serializes whichever model instance we return.
@router.get("/scans/{scan_id}", response_model=None)
def read_scan(scan_id: str, session: SessionDep) -> ScanReport | ScanStatus:
    row = queue.get_scan(session, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if row.status == "done" and row.result is not None:
        # Stored blob is a ScanReport.model_dump — clients get the identical shape
        # the synchronous endpoint used to return. (A done row always has a result:
        # the ck_scans_done_has_result constraint enforces it; the guard is defensive.)
        return ScanReport.model_validate(row.result)
    return ScanStatus(id=row.id, status=cast(ScanState, row.status), error=row.error)
