import { bytes, date, dateTime } from "../format";
import type { Report } from "../types";

interface Props {
  report: Report;
}

type Fact = [string, string | null];

function factsFor(report: Report): Fact[] {
  const detail = report.detail;

  if (detail.kind === "file") {
    return [
      ["type", detail.type_description],
      ["size", bytes(detail.size)],
      ["md5", detail.md5],
      ["sha-256", detail.sha256],
      ["signer", detail.signer],
      ["signature", detail.signature_valid === null ? null : detail.signature_valid ? "valid" : "invalid"],
      ["known names", detail.names.slice(0, 4).join(", ") || null],
      ["first seen", date(report.first_seen)],
      ["last seen", date(report.last_seen)],
    ];
  }

  if (detail.kind === "ip") {
    return [
      ["asn", detail.asn ? `AS${detail.asn}` : null],
      ["operator", detail.as_owner],
      ["network", detail.network],
      ["country", detail.country],
      ["registry", detail.registry],
      ["abuseipdb", detail.abuseipdb ? `${detail.abuseipdb.confidence_score}% · ${detail.abuseipdb.total_reports} reports` : null],
      ["usage", detail.abuseipdb?.usage_type ?? null],
      ["last analysed", date(report.last_analysed)],
    ];
  }

  if (detail.kind === "domain") {
    const rank = Object.entries(detail.popularity_ranks)[0];
    return [
      ["registrar", detail.registrar],
      ["registered", date(detail.created_at)],
      ["expires", date(detail.expires_at)],
      ["popularity", rank ? `#${rank[1]} (${rank[0]})` : null],
      ["categories", Object.values(detail.categories).slice(0, 3).join(", ") || null],
      ["last analysed", date(report.last_analysed)],
    ];
  }

  return [
    ["final url", detail.final_url],
    ["title", detail.title],
    ["http status", detail.response_code ? String(detail.response_code) : null],
    ["content type", detail.content_type],
    ["categories", Object.values(detail.categories).slice(0, 3).join(", ") || null],
    ["first seen", date(report.first_seen)],
  ];
}

/** The indicator's identifying attributes, chosen for its type. */
export function FactsPanel({ report }: Props) {
  const facts = factsFor(report).filter(([, value]) => value && value !== "—");

  return (
    <aside className="facts">
      <p className="eyebrow">{report.ioc_type}</p>
      <dl>
        {facts.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd className="mono-value">{value}</dd>
          </div>
        ))}
        <div>
          <dt>reputation</dt>
          <dd>
            {report.reputation} · {report.community_votes_malicious} malicious votes
          </dd>
        </div>
        <div>
          <dt>retrieved</dt>
          <dd>
            {dateTime(report.retrieved_at)}
            {report.cached && <span className="muted"> · from cache</span>}
          </dd>
        </div>
        <div>
          <dt>source</dt>
          <dd>
            <a href={report.source_link} target="_blank" rel="noreferrer noopener">
              open in VirusTotal
            </a>
          </dd>
        </div>
      </dl>
    </aside>
  );
}
