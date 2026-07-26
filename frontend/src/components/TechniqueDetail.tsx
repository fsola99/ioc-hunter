import { useEffect } from "react";

import type { AttackTechniqueDetail } from "../types";

interface Props {
  detail: AttackTechniqueDetail;
  onClose: () => void;
  onOpen: (id: string) => void;
}

/** One technique in full: where it sits, what it covers, and what mitigates it. */
export function TechniqueDetail({ detail, onClose, onOpen }: Props) {
  const { technique, tactic_names, subtechniques, parent } = detail;

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="drawer-backdrop" onClick={onClose} role="presentation">
      <aside
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-label={`${technique.id} ${technique.name}`}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="drawer-head">
          <div>
            <p className="eyebrow">
              {parent ? `${parent.id} · sub-technique` : "technique"}
            </p>
            <h2 className="drawer-title">
              <span className="technique-id">{technique.id}</span> {technique.name}
            </h2>
          </div>
          <button className="drawer-close" type="button" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>

        <div className="drawer-body">
          {parent && (
            <button className="drawer-parent" type="button" onClick={() => onOpen(parent.id)}>
              ↑ {parent.id} {parent.name}
            </button>
          )}

          <div className="chip-row">
            {Object.entries(tactic_names).map(([id, name]) => (
              <span className="tag" key={id}>
                {id} {name}
              </span>
            ))}
          </div>

          {technique.description && <p className="drawer-text">{technique.description}</p>}

          <section className="drawer-section">
            <p className="eyebrow">platforms</p>
            <div className="chip-row">
              {technique.platforms.map((platform) => (
                <span className="tag" key={platform}>
                  {platform}
                </span>
              ))}
            </div>
          </section>

          <section className="drawer-section">
            <p className="eyebrow">
              mitigations
              {technique.mitigations.length === 0 && " — none recorded"}
            </p>
            {technique.mitigations.length > 0 && (
              <div className="mitigation-list">
                {technique.mitigations.map((mitigation) => (
                  <span className="mitigation" key={mitigation.id}>
                    {mitigation.id} {mitigation.name}
                  </span>
                ))}
              </div>
            )}
          </section>

          {subtechniques.length > 0 && (
            <section className="drawer-section">
              <p className="eyebrow">sub-techniques · {subtechniques.length}</p>
              <ul className="sub-list">
                {subtechniques.map((sub) => (
                  <li key={sub.id}>
                    <button type="button" onClick={() => onOpen(sub.id)}>
                      <span className="technique-id">{sub.id}</span> {sub.name}
                      {sub.mitigations.length > 0 && (
                        <span className="sub-count">
                          {sub.mitigations.length}{" "}
                          {sub.mitigations.length === 1 ? "mitigation" : "mitigations"}
                        </span>
                      )}
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {technique.url && (
            <p className="drawer-source">
              <a href={technique.url} target="_blank" rel="noreferrer noopener">
                open on attack.mitre.org
              </a>
            </p>
          )}
        </div>
      </aside>
    </div>
  );
}
