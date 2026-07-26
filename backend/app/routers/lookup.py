from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from ..dependencies import HistoryDep, IndicatorDep, ServiceDep, SessionDep
from ..models import BehaviourReport, ClassificationResult, RelationsReport, Report
from ..services.export import reports_to_csv

router = APIRouter(prefix="/api", tags=["lookup"])


@router.get("/classify", response_model=ClassificationResult)
def classify_indicator(ioc: IndicatorDep) -> ClassificationResult:
    """Report how the service interprets a candidate indicator, without querying any provider."""
    return ClassificationResult(
        raw_input=ioc.raw, indicator=ioc.value, ioc_type=ioc.type, family=ioc.family
    )


@router.get("/lookup", response_model=Report)
async def lookup_indicator(
    ioc: IndicatorDep, service: ServiceDep, history: HistoryDep, session_id: SessionDep
) -> Report:
    """Return the threat intelligence report for an indicator and record it in session history."""
    report = await service.lookup(ioc)
    history.record(session_id, report)
    return report


@router.get("/behaviour", response_model=BehaviourReport)
async def lookup_behaviour(ioc: IndicatorDep, service: ServiceDep) -> BehaviourReport:
    """Return sandbox behaviour and ATT&CK coverage for a file indicator."""
    if ioc.family != "file":
        raise HTTPException(
            status_code=400,
            detail=f"Sandbox behaviour is only available for file hashes, not {ioc.type.value}.",
        )
    return await service.behaviour(ioc)


@router.get("/relations", response_model=RelationsReport)
async def lookup_relations(ioc: IndicatorDep, service: ServiceDep) -> RelationsReport:
    """Return indicators connected to the one supplied."""
    return await service.relations(ioc)


@router.get("/history", response_model=list[Report])
def read_history(history: HistoryDep, session_id: SessionDep) -> list[Report]:
    """Return this session's recorded lookups, most recent first."""
    return history.list(session_id)


@router.delete("/history")
def clear_history(history: HistoryDep, session_id: SessionDep) -> dict[str, int]:
    """Discard this session's recorded lookups."""
    return {"removed": history.clear(session_id)}


@router.get("/history/export.csv", response_class=Response)
def export_history(history: HistoryDep, session_id: SessionDep) -> Response:
    """Return this session's recorded lookups as a CSV attachment, one row per indicator."""
    reports = history.list(session_id)
    if not reports:
        raise HTTPException(status_code=404, detail="No lookups recorded in this session yet.")
    return Response(
        content=reports_to_csv(reports),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="ioc-hunter-export.csv"'},
    )
