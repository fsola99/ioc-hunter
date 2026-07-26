import { severity } from "../format";
import type { SandboxMitre } from "../types";

interface Props {
  sandboxes: SandboxMitre[];
  onOpenTechnique: (id: string) => void;
}

/** ATT&CK tactics and techniques observed in detonation, each with its mitigations. */
export function AttackPanel({ sandboxes, onOpenTechnique }: Props) {
  if (sandboxes.length === 0) {
    return (
      <p className="muted">
        No sandbox reported ATT&amp;CK techniques for this file. That usually means it has not been
        detonated, not that it is safe.
      </p>
    );
  }

  return (
    <div>
      {sandboxes.map((sandbox) => (
        <section className="sandbox" key={sandbox.sandbox}>
          <p className="eyebrow">sandbox · {sandbox.sandbox}</p>
          {sandbox.tactics.map((tactic) => (
            <div className="tactic" key={`${sandbox.sandbox}-${tactic.id}`}>
              <p className="tactic-name">
                {tactic.id} {tactic.name}
              </p>
              {tactic.techniques.map((technique) => (
                <article className="technique" key={`${tactic.id}-${technique.id}`}>
                  <header className="technique-head">
                    <button
                      className="technique-id technique-link"
                      type="button"
                      onClick={() => onOpenTechnique(technique.id)}
                      title={`Open ${technique.id} in the ATT&CK matrix`}
                    >
                      {technique.id}
                    </button>
                    <span className="technique-name">{technique.name}</span>
                    {technique.severities.length > 0 && (
                      <span className="severity">{technique.severities.map(severity).join(" / ")}</span>
                    )}
                  </header>

                  {technique.signatures.length > 0 && (
                    <ul className="signatures">
                      {technique.signatures.map((signature, index) => (
                        <li key={index}>{signature}</li>
                      ))}
                    </ul>
                  )}

                  {technique.mitigations.length > 0 && (
                    <div className="mitigations">
                      <p className="eyebrow">recommended mitigations</p>
                      <div className="mitigation-list">
                        {technique.mitigations.map((mitigation) => (
                          <span className="mitigation" key={mitigation.id}>
                            {mitigation.id} {mitigation.name}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </article>
              ))}
            </div>
          ))}
        </section>
      ))}
    </div>
  );
}
