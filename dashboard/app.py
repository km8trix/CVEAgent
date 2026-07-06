"""Palisade scan dashboard (M3). Read-only view over the scans table.

Run: `make dashboard` (or `uv run --extra dashboard streamlit run dashboard/app.py`).
Lives outside src/ so its Streamlit dependency stays out of the core API/worker install and
out of mypy's checked paths; the testable aggregation lives in `palisade.dashboard`.
"""

import streamlit as st

from palisade.dashboard import overview, recent_scans, scan_row
from palisade.db.base import SessionLocal
from palisade.github_app.render import render_section
from palisade.models.finding import ScanReport

st.set_page_config(page_title="Palisade", page_icon="🛡️", layout="wide")
st.title("🛡️ Palisade — scan dashboard")

with SessionLocal() as session:
    scans = recent_scans(session, limit=100)

if not scans:
    st.info("No scans yet — enqueue one via `POST /scan` or the GitHub PR webhook.")
    st.stop()

o = overview(scans)
p95 = o["p95_latency_ms"]
cols = st.columns(5)
cols[0].metric("Scans", o["scans"])
cols[1].metric("Done", o["done"])
cols[2].metric("Findings", o["findings"])
cols[3].metric("KEV", o["kev"])
cols[4].metric("p95 latency", f"{p95} ms" if p95 is not None else "—")

st.subheader("Recent scans")
st.dataframe([scan_row(s) for s in scans], use_container_width=True)

st.subheader("Findings")
done = {f"{s.id[:8]} · {s.filename} ({s.status})": s for s in scans if s.result is not None}
if done:
    picked = done[st.selectbox("Scan", list(done))]
    st.markdown(render_section(ScanReport.model_validate(picked.result)))
else:
    st.caption("No completed scans with a report yet.")
