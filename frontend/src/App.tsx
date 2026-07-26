import { useCallback, useEffect, useMemo, useState } from "react";

import * as api from "./api";
import { ApiError } from "./api";
import { AttackPanel } from "./components/AttackPanel";
import { BehaviourPanel } from "./components/BehaviourPanel";
import { EmptyState } from "./components/EmptyState";
import { ErrorNotice } from "./components/ErrorNotice";
import { FactsPanel } from "./components/FactsPanel";
import { HistoryRail } from "./components/HistoryRail";
import { RelationsPanel } from "./components/RelationsPanel";
import { SearchBar } from "./components/SearchBar";
import { VendorTable } from "./components/VendorTable";
import { VerdictBanner } from "./components/VerdictBanner";
import type { BehaviourReport, RelationsReport, Report, ServiceStatus } from "./types";

type TabId = "engines" | "attack" | "behaviour" | "relations";

const TAB_LABELS: Record<TabId, string> = {
  engines: "Engines",
  attack: "ATT&CK",
  behaviour: "Behaviour",
  relations: "Related",
};

function tabsFor(report: Report): TabId[] {
  if (report.detail.kind === "file") return ["engines", "attack", "behaviour", "relations"];
  if (report.detail.kind === "url") return ["engines"];
  return ["engines", "relations"];
}

export function App() {
  const [query, setQuery] = useState("");
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState<TabId>("engines");
  const [entries, setEntries] = useState<Report[]>([]);
  const [service, setService] = useState<ServiceStatus | null>(null);

  const [behaviour, setBehaviour] = useState<BehaviourReport | null>(null);
  const [relations, setRelations] = useState<RelationsReport | null>(null);
  const [demandBusy, setDemandBusy] = useState(false);
  const [demandError, setDemandError] = useState<string | null>(null);

  useEffect(() => {
    api.status().then(setService).catch(() => setService(null));
    api.history().then(setEntries).catch(() => setEntries([]));
  }, []);

  const runLookup = useCallback(async (indicator: string) => {
    setQuery(indicator);
    setBusy(true);
    setError(null);
    setBehaviour(null);
    setRelations(null);
    setDemandError(null);
    setTab("engines");

    try {
      const result = await api.lookup(indicator);
      setReport(result);
      setEntries(await api.history());
    } catch (caught) {
      setReport(null);
      setError(caught instanceof ApiError ? caught : new ApiError(String(caught), 0));
    } finally {
      setBusy(false);
    }
  }, []);

  const loadBehaviour = useCallback(async () => {
    if (!report) return;
    setDemandBusy(true);
    setDemandError(null);
    try {
      setBehaviour(await api.behaviour(report.indicator));
    } catch (caught) {
      setDemandError(caught instanceof ApiError ? caught.message : String(caught));
    } finally {
      setDemandBusy(false);
    }
  }, [report]);

  const loadRelations = useCallback(async () => {
    if (!report) return;
    setDemandBusy(true);
    setDemandError(null);
    try {
      setRelations(await api.relations(report.indicator));
    } catch (caught) {
      setDemandError(caught instanceof ApiError ? caught.message : String(caught));
    } finally {
      setDemandBusy(false);
    }
  }, [report]);

  const clearHistory = useCallback(async () => {
    await api.clearHistory();
    setEntries([]);
  }, []);

  const tabs = useMemo(() => (report ? tabsFor(report) : []), [report]);
  const verdict = report?.verdict ?? "unknown";

  return (
    <div className="shell" data-verdict={verdict}>
      <header className="statusbar">
        <p className="wordmark">
          IoC Hunter <span>v{service?.version ?? "—"}</span>
        </p>
        <div className="providers">
          {service?.providers.map((provider) => (
            <span
              className="provider"
              key={provider.name}
              data-on={provider.configured}
              title={provider.detail}
            >
              {provider.name}
            </span>
          ))}
        </div>
      </header>

      <div className="workspace">
        <main className="main">
          <SearchBar value={query} busy={busy} onChange={setQuery} onSubmit={runLookup} />

          {busy && <p className="scanning">querying providers</p>}
          {error && !busy && <ErrorNotice error={error} />}
          {!report && !error && !busy && <EmptyState onPick={runLookup} />}

          {report && !busy && (
            <>
              <VerdictBanner report={report} />

              <div className="panels">
                <FactsPanel report={report} />

                <section className="tabs">
                  <div className="tablist" role="tablist">
                    {tabs.map((id) => (
                      <button
                        key={id}
                        className="tab"
                        role="tab"
                        type="button"
                        aria-selected={tab === id}
                        onClick={() => setTab(id)}
                      >
                        {TAB_LABELS[id]}
                        {id === "engines" && (
                          <span className="tab-count">{report.vendors.length}</span>
                        )}
                      </button>
                    ))}
                  </div>

                  <div className="tabpanel" role="tabpanel">
                    {tab === "engines" && <VendorTable vendors={report.vendors} />}

                    {tab === "attack" &&
                      (behaviour ? (
                        <AttackPanel sandboxes={behaviour.mitre} />
                      ) : (
                        <OnDemand
                          label="Load sandbox report"
                          busy={demandBusy}
                          error={demandError}
                          onLoad={loadBehaviour}
                          explanation="ATT&CK coverage comes from VirusTotal's sandbox detonations and costs a separate request, so it loads only when you ask for it."
                        />
                      ))}

                    {tab === "behaviour" &&
                      (behaviour ? (
                        <BehaviourPanel behaviour={behaviour} />
                      ) : (
                        <OnDemand
                          label="Load sandbox report"
                          busy={demandBusy}
                          error={demandError}
                          onLoad={loadBehaviour}
                          explanation="Runtime activity comes from VirusTotal's sandbox detonations and costs a separate request, so it loads only when you ask for it."
                        />
                      ))}

                    {tab === "relations" &&
                      (relations ? (
                        <RelationsPanel relations={relations} onPivot={runLookup} />
                      ) : (
                        <OnDemand
                          label="Load connected indicators"
                          busy={demandBusy}
                          error={demandError}
                          onLoad={loadRelations}
                          explanation="Connected indicators cost a separate request. Load them when you want to pivot from this one."
                        />
                      ))}
                  </div>
                </section>
              </div>
            </>
          )}
        </main>

        <HistoryRail
          entries={entries}
          current={report?.indicator ?? null}
          onSelect={runLookup}
          onClear={clearHistory}
        />
      </div>
    </div>
  );
}

interface OnDemandProps {
  label: string;
  explanation: string;
  busy: boolean;
  error: string | null;
  onLoad: () => void;
}

function OnDemand({ label, explanation, busy, error, onLoad }: OnDemandProps) {
  return (
    <div className="demand">
      <p>{error ?? explanation}</p>
      <button className="demand-button" type="button" onClick={onLoad} disabled={busy}>
        {busy ? "Loading" : label}
      </button>
    </div>
  );
}
