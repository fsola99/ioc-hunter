from __future__ import annotations

from collections import OrderedDict, deque

from ..models import Report


class HistoryStore:
    """Keeps each browser session's recent lookups, most recent first.

    Sessions are isolated from one another, so an export only ever contains the
    indicators that session looked up.
    """

    def __init__(self, max_sessions: int = 500, max_per_session: int = 50) -> None:
        """Create a store bounded to `max_sessions`, each holding `max_per_session` reports."""
        self._max_sessions = max_sessions
        self._max_per_session = max_per_session
        self._sessions: OrderedDict[str, deque[Report]] = OrderedDict()

    def record(self, session_id: str, report: Report) -> None:
        """Add `report` to `session_id`'s history, replacing any earlier lookup of the same indicator."""
        entries = self._sessions.get(session_id)
        if entries is None:
            entries = deque(maxlen=self._max_per_session)
            self._sessions[session_id] = entries
            self._evict_oldest_sessions()

        existing = [item for item in entries if item.indicator != report.indicator]
        entries.clear()
        entries.append(report)
        entries.extend(existing)
        self._sessions.move_to_end(session_id)

    def list(self, session_id: str) -> list[Report]:
        """Return `session_id`'s recorded lookups, most recent first."""
        return list(self._sessions.get(session_id, ()))

    def clear(self, session_id: str) -> int:
        """Discard `session_id`'s history and return how many reports were removed."""
        entries = self._sessions.pop(session_id, None)
        return len(entries) if entries else 0

    def _evict_oldest_sessions(self) -> None:
        while len(self._sessions) > self._max_sessions:
            self._sessions.popitem(last=False)
