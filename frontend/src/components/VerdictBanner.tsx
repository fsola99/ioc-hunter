import type { Report } from "../types";
import { EngineMeter } from "./EngineMeter";

interface Props {
  report: Report;
}

function threatLine(report: Report): string | null {
  const detail = report.detail;
  if (detail.kind === "file") return detail.threat_label;
  if (detail.kind === "url") return detail.title;
  if (detail.kind === "ip") {
    return detail.as_owner ? `${detail.as_owner}${detail.country ? ` · ${detail.country}` : ""}` : null;
  }
  return detail.registrar;
}

/** The result headline: verdict, detection ratio, and the per-engine meter. */
export function VerdictBanner({ report }: Props) {
  const threat = threatLine(report);

  return (
    <section className="verdict" data-verdict={report.verdict} aria-live="polite">
      <div className="verdict-head">
        <div>
          <p className="eyebrow">verdict</p>
          <h2 className="verdict-word">{report.verdict}</h2>
        </div>
        <div className="verdict-ratio">
          <p className="eyebrow">engines flagging</p>
          <strong>{report.detection_ratio}</strong>
        </div>
      </div>

      <p className="verdict-indicator mono-value">{report.indicator}</p>
      {threat && <p className="verdict-threat mono-value">{threat}</p>}

      <EngineMeter vendors={report.vendors} stats={report.stats} />

      {report.tags.length > 0 && (
        <div className="tag-row">
          {report.tags.map((tag) => (
            <span className="tag" key={tag}>
              {tag}
            </span>
          ))}
        </div>
      )}
    </section>
  );
}
