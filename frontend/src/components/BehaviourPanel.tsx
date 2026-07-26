import type { BehaviourReport } from "../types";

interface Props {
  behaviour: BehaviourReport;
}

const GROUPS: [keyof BehaviourReport, string][] = [
  ["processes_created", "processes created"],
  ["processes_terminated", "processes terminated"],
  ["services_started", "services started"],
  ["mutexes_created", "mutexes created"],
  ["files_written", "files written"],
  ["files_opened", "files opened"],
  ["registry_keys_opened", "registry keys opened"],
  ["modules_loaded", "modules loaded"],
];

/** Runtime activity recorded while the file was detonated. */
export function BehaviourPanel({ behaviour }: Props) {
  const populated = GROUPS.filter(([key]) => (behaviour[key] as string[]).length > 0);
  const hasNetwork = behaviour.dns_lookups.length > 0;

  if (populated.length === 0 && !hasNetwork) {
    return (
      <p className="muted">
        No sandbox behaviour is recorded for this file. Files that have never been detonated report
        nothing here.
      </p>
    );
  }

  return (
    <div className="behaviour-grid">
      {hasNetwork && (
        <div className="behaviour-group">
          <h4>dns lookups</h4>
          <ul>
            {behaviour.dns_lookups.map((lookup) => (
              <li key={lookup.hostname}>
                {lookup.hostname}
                {lookup.resolved_ips.length > 0 && (
                  <span className="muted"> → {lookup.resolved_ips.join(", ")}</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {populated.map(([key, label]) => (
        <div className="behaviour-group" key={key}>
          <h4>{label}</h4>
          <ul>
            {(behaviour[key] as string[]).map((entry, index) => (
              <li key={`${key}-${index}`}>{entry}</li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
