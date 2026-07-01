"""Normalize raw OSV records into the internal AdvisoryRecord (itself OSV-shaped).

NVD/GHSA get their own normalizers into the same shape later; OSV is nearly 1:1.
See IMPLEMENTATION_PLAN.md sections 4.1 and 5.
"""

import hashlib
import json
from typing import Any

from palisade.models.advisory import (
    AdvisoryRecord,
    AffectedPackage,
    Event,
    Range,
    Severity,
    SeverityBucket,
)

# Only npm + PyPI are in scope (IMPLEMENTATION_PLAN.md section 10).
_SUPPORTED_ECOSYSTEMS = {"npm", "PyPI"}

# CVSS vector types we store, in preference order (v2 has a different vector format).
_CVSS_PREFERENCE = ("CVSS_V3", "CVSS_V4")

_GHSA_SEVERITY_BUCKET: dict[str, SeverityBucket] = {
    "LOW": "low",
    "MODERATE": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


def content_hash(raw: dict[str, Any]) -> str:
    """Stable digest of a raw record for skip-unchanged ingestion.

    Deliberately hashes the whole record including `modified`: an OSV metadata touch
    bumps `modified`, which we treat as "changed" and re-ingest.
    """
    return hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()


def _severity(raw: dict[str, Any]) -> Severity:
    severities = raw.get("severity") or []
    vector = None
    for pref in _CVSS_PREFERENCE:
        match = next((s for s in severities if s.get("type") == pref), None)
        if match is not None:
            vector = match.get("score")
            break
    ghsa = (raw.get("database_specific") or {}).get("severity")
    bucket = _GHSA_SEVERITY_BUCKET.get(ghsa.upper()) if isinstance(ghsa, str) else None
    return Severity(cvss_vector=vector, bucket=bucket)


def _affected(raw: dict[str, Any]) -> list[AffectedPackage]:
    out: list[AffectedPackage] = []
    for entry in raw.get("affected", []):
        pkg = entry.get("package", {})
        ecosystem = pkg.get("ecosystem")
        if ecosystem not in _SUPPORTED_ECOSYSTEMS:
            continue
        ranges = [
            Range(
                type=r.get("type", "ECOSYSTEM"), events=[Event(**ev) for ev in r.get("events", [])]
            )
            for r in entry.get("ranges", [])
        ]
        out.append(
            AffectedPackage(
                ecosystem=ecosystem,
                name=pkg.get("name", ""),
                ranges=ranges,
                versions=entry.get("versions", []),
                database_specific=entry.get("database_specific", {}),
            )
        )
    return out


def normalize_osv(raw: dict[str, Any]) -> AdvisoryRecord:
    """Map a raw OSV record to AdvisoryRecord. Raises ValueError for records that
    should be skipped (withdrawn) or that are malformed (missing id/modified)."""
    osv_id = raw.get("id")
    if not osv_id:
        raise ValueError("OSV record missing required field 'id'")
    if "withdrawn" in raw:
        raise ValueError(f"OSV record {osv_id} is withdrawn; skip it")
    modified = raw.get("modified")
    if not modified:
        raise ValueError(f"OSV record {osv_id} missing required field 'modified'")
    return AdvisoryRecord(
        id=f"osv:{osv_id}",
        source="osv",
        source_id=osv_id,
        aliases=raw.get("aliases", []),
        summary=raw.get("summary", ""),
        details=raw.get("details", ""),
        severity=_severity(raw),
        cwe_ids=(raw.get("database_specific") or {}).get("cwe_ids", []),
        affected=_affected(raw),
        references=[ref["url"] for ref in raw.get("references", []) if "url" in ref],
        published=raw.get("published", modified),
        modified=modified,
        content_hash=content_hash(raw),
    )
