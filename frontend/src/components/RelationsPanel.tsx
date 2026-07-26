import { date } from "../format";
import type { RelationsReport } from "../types";

interface Props {
  relations: RelationsReport;
  onPivot: (indicator: string) => void;
}

const RELATION_LABELS: Record<string, string> = {
  contacted_domains: "Domains contacted during detonation",
  contacted_ips: "Addresses contacted during detonation",
  resolutions: "Observed DNS resolutions",
};

/** Indicators connected to the current one, each a starting point for the next lookup. */
export function RelationsPanel({ relations, onPivot }: Props) {
  if (relations.items.length === 0) {
    return <p className="muted">No connected indicators are recorded for this one.</p>;
  }

  return (
    <div className="table-scroll">
      <table>
        <caption className="eyebrow" style={{ textAlign: "left", paddingBottom: "0.75rem" }}>
          {RELATION_LABELS[relations.relation] ?? relations.relation}
          {relations.truncated && " · showing the first 40"}
        </caption>
        <thead>
          <tr>
            <th scope="col">Indicator</th>
            <th scope="col">Detections</th>
            <th scope="col">Context</th>
            <th scope="col">Observed</th>
          </tr>
        </thead>
        <tbody>
          {relations.items.map((item) => (
            <tr key={item.indicator}>
              <td className="value">
                <button
                  type="button"
                  className="dot"
                  data-verdict={item.verdict}
                  onClick={() => onPivot(item.indicator)}
                  title={`Look up ${item.indicator}`}
                >
                  {item.indicator}
                </button>
              </td>
              <td>
                {item.total_engines > 0 ? `${item.detections}/${item.total_engines}` : "—"}
              </td>
              <td>{item.detail ?? "—"}</td>
              <td>{date(item.observed_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
