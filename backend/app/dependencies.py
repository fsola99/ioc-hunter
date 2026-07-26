from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, Query, Request

from .config import Settings, get_settings
from .ioc import ClassifiedIoC, classify
from .services.history import HistoryStore
from .services.intel import IntelService

SESSION_COOKIE = "ioc_hunter_session"

_history = HistoryStore()
_service: IntelService | None = None


def get_history() -> HistoryStore:
    """Return the process-wide lookup history store."""
    return _history


def get_service(settings: Annotated[Settings, Depends(get_settings)]) -> IntelService:
    """Return the process-wide intelligence service."""
    global _service
    if _service is None:
        _service = IntelService(settings)
    return _service


def get_session_id(request: Request) -> str:
    """Return the caller's session id, minting one when the request carries none.

    The value is echoed back as a cookie by the response middleware.
    """
    existing = request.cookies.get(SESSION_COOKIE)
    if existing:
        return existing
    minted = request.state.session_id = uuid.uuid4().hex
    return minted


def get_indicator(
    indicator: Annotated[
        str,
        Query(
            min_length=1,
            max_length=2048,
            description="A hash, IP address, domain or URL. Defanged input is accepted.",
        ),
    ],
) -> ClassifiedIoC:
    """Return the classified indicator named by the `indicator` query parameter.

    Raises:
        UnrecognizedIoCError: If the value matches no supported indicator type.
    """
    return classify(indicator)


ServiceDep = Annotated[IntelService, Depends(get_service)]
HistoryDep = Annotated[HistoryStore, Depends(get_history)]
SessionDep = Annotated[str, Depends(get_session_id)]
IndicatorDep = Annotated[ClassifiedIoC, Depends(get_indicator)]
