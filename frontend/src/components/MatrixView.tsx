import { useEffect, useState } from "react";

import * as api from "../api";
import { attackExportUrl } from "../api";
import type { AttackMatrix, AttackTechniqueDetail } from "../types";
import { TechniqueDetail } from "./TechniqueDetail";

interface Props {
  highlighted: Set<string>;
  openTechnique: string | null;
  onOpenTechnique: (id: string | null) => void;
}

/**
 * The Enterprise ATT&CK matrix, browsable offline from the bundled catalogue.
 *
 * Cells are marked by whether ATT&CK records a mitigation for the technique,
 * which is the question a defender is usually asking of the matrix.
 */
export function MatrixView({ highlighted, openTechnique, onOpenTechnique }: Props) {
  const [matrix, setMatrix] = useState<AttackMatrix | null>(null);
  const [detail, setDetail] = useState<AttackTechniqueDetail | null>(null);
  const [query, setQuery] = useState("");
  const [platform, setPlatform] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      api
        .attackMatrix(query, platform)
        .then((result) => {
          setMatrix(result);
          setError(null);
        })
        .catch((caught) => setError(String(caught)));
    }, 180);
    return () => window.clearTimeout(timer);
  }, [query, platform]);

  useEffect(() => {
    if (!openTechnique) {
      setDetail(null);
      return;
    }
    api
      .attackTechnique(openTechnique)
      .then(setDetail)
      .catch(() => setDetail(null));
  }, [openTechnique]);

  if (error) {
    return <p className="muted">Could not load the ATT&amp;CK catalogue: {error}</p>;
  }

  if (!matrix) {
    return <p className="scanning">loading catalogue</p>;
  }

  return (
    <section className="matrix-view">
      <div className="matrix-controls">
        <div className="matrix-filters">
          <input
            className="search-input matrix-search"
            type="search"
            placeholder="Filter by technique id or name"
            value={query}
            spellCheck={false}
            onChange={(event) => setQuery(event.target.value)}
            aria-label="Filter techniques"
          />
          <select
            className="matrix-select"
            value={platform}
            onChange={(event) => setPlatform(event.target.value)}
            aria-label="Filter by platform"
          >
            <option value="">All platforms</option>
            {matrix.platforms.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </div>

        <div className="matrix-meta">
          <span>
            <b>{matrix.technique_count}</b> techniques
          </span>
          <span className="matrix-key">
            <i className="key-swatch" data-covered="true" /> mitigations recorded
          </span>
          <span className="matrix-key">
            <i className="key-swatch" data-covered="false" /> none recorded
          </span>
          {highlighted.size > 0 && (
            <span className="matrix-key">
              <i className="key-swatch" data-observed="true" /> seen in the last sandbox report
            </span>
          )}
          <a href={attackExportUrl} download>
            Export CSV
          </a>
        </div>
      </div>

      {matrix.technique_count === 0 ? (
        <p className="muted matrix-empty">
          No technique matches that filter. Try a shorter term, or clear the platform.
        </p>
      ) : (
        <div className="matrix-scroll">
          <div className="matrix-grid">
            {matrix.tactics.map((tactic) => (
              <div className="matrix-column" key={tactic.id}>
                <header className="matrix-column-head" title={tactic.description}>
                  <p className="matrix-tactic">{tactic.name}</p>
                  <p className="matrix-tactic-meta">
                    {tactic.id} · {tactic.techniques.length}
                  </p>
                </header>

                <div className="matrix-cells">
                  {tactic.techniques.map((technique) => (
                    <button
                      className="matrix-cell"
                      type="button"
                      key={`${tactic.id}-${technique.id}`}
                      data-covered={technique.mitigation_count > 0}
                      data-observed={highlighted.has(technique.id)}
                      onClick={() => onOpenTechnique(technique.id)}
                      title={`${technique.id} ${technique.name}`}
                    >
                      <span className="matrix-cell-id">{technique.id}</span>
                      <span className="matrix-cell-name">{technique.name}</span>
                      {technique.subtechnique_count > 0 && (
                        <span className="matrix-cell-subs">
                          {technique.subtechnique_count}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {detail && (
        <TechniqueDetail
          detail={detail}
          onClose={() => onOpenTechnique(null)}
          onOpen={onOpenTechnique}
        />
      )}
    </section>
  );
}
