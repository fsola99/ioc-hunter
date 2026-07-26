from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from ..models import AttackMatrix, AttackTechniqueDetail
from ..services import attack

router = APIRouter(prefix="/api/attack", tags=["attack"])


@router.get("/matrix", response_model=AttackMatrix)
def read_matrix(
    q: Annotated[str, Query(max_length=120, description="Text matched against id and name.")] = "",
    platform: Annotated[str, Query(max_length=60, description="ATT&CK platform name.")] = "",
) -> AttackMatrix:
    """Return the Enterprise ATT&CK matrix, optionally narrowed by text and platform."""
    return attack.matrix(query=q, platform=platform)


@router.get("/techniques/{technique_id}", response_model=AttackTechniqueDetail)
def read_technique(technique_id: str) -> AttackTechniqueDetail:
    """Return one technique with its sub-techniques, parent and tactic names."""
    entry = attack.technique(technique_id)
    if entry is None:
        raise HTTPException(
            status_code=404, detail=f"{technique_id} is not in the ATT&CK catalogue."
        )

    tactics = {tactic.id: tactic.name for tactic in attack.matrix().tactics}
    return AttackTechniqueDetail(
        technique=entry,
        tactic_names={
            tactic_id: tactics[tactic_id] for tactic_id in entry.tactics if tactic_id in tactics
        },
        subtechniques=attack.subtechniques_of(entry.id),
        parent=attack.technique(entry.parent) if entry.parent else None,
    )


@router.get("/export.csv", response_class=Response)
def export_catalogue() -> Response:
    """Return the whole catalogue as a CSV attachment, one row per technique."""
    return Response(
        content=attack.to_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="attack-techniques.csv"'},
    )
