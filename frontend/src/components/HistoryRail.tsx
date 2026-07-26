import { exportUrl } from "../api";
import { truncate } from "../format";
import type { Report } from "../types";

interface Props {
  entries: Report[];
  current: string | null;
  onSelect: (indicator: string) => void;
  onClear: () => void;
}

/** This session's lookups, kept as a trail the analyst can step back through. */
export function HistoryRail({ entries, current, onSelect, onClear }: Props) {
  return (
    <aside className="rail">
      <div className="rail-head">
        <p className="eyebrow">session trail</p>
        <span className="muted">{entries.length}</span>
      </div>

      {entries.length === 0 ? (
        <p className="muted" style={{ marginTop: "0.9rem" }}>
          Indicators you look up are listed here, newest first.
        </p>
      ) : (
        <>
          <div className="rail-actions">
            <a href={exportUrl} download>
              Export CSV
            </a>
            <button type="button" onClick={onClear}>
              Clear
            </button>
          </div>

          <ul className="rail-list">
            {entries.map((entry) => (
              <li key={entry.indicator}>
                <button
                  type="button"
                  className="rail-item"
                  aria-current={entry.indicator === current}
                  onClick={() => onSelect(entry.indicator)}
                >
                  <span className="rail-indicator mono-value">{truncate(entry.indicator, 30)}</span>
                  <span className="rail-meta">
                    <span className="dot" data-verdict={entry.verdict}>
                      {entry.ioc_type}
                    </span>
                    <span>{entry.detection_ratio}</span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </aside>
  );
}
