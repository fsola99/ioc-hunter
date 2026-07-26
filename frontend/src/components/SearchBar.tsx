import { useEffect, useState, type FormEvent } from "react";

import { classify } from "../api";
import type { ClassificationResult } from "../types";

interface Props {
  value: string;
  busy: boolean;
  onChange: (value: string) => void;
  onSubmit: (value: string) => void;
}

/** The indicator input, echoing how the service reads what is being typed. */
export function SearchBar({ value, busy, onChange, onSubmit }: Props) {
  const [reading, setReading] = useState<ClassificationResult | null>(null);
  const [unreadable, setUnreadable] = useState(false);

  useEffect(() => {
    const trimmed = value.trim();
    if (trimmed.length < 3) {
      setReading(null);
      setUnreadable(false);
      return;
    }

    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      classify(trimmed)
        .then((result) => {
          if (!controller.signal.aborted) {
            setReading(result);
            setUnreadable(false);
          }
        })
        .catch(() => {
          if (!controller.signal.aborted) {
            setReading(null);
            setUnreadable(true);
          }
        });
    }, 220);

    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [value]);

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (value.trim()) onSubmit(value.trim());
  }

  const refanged = reading && reading.indicator !== reading.raw_input.trim();

  return (
    <form className="search" onSubmit={handleSubmit}>
      <label className="eyebrow search-label" htmlFor="indicator">
        indicator
      </label>
      <div className="search-row">
        <div className="search-field">
          <input
            id="indicator"
            className="search-input mono-value"
            type="text"
            autoComplete="off"
            spellCheck={false}
            autoFocus
            placeholder="hash, IP address, domain or URL"
            value={value}
            onChange={(event) => onChange(event.target.value)}
          />
        </div>
        <button className="search-submit" type="submit" disabled={busy || !value.trim()}>
          {busy ? "Hunting" : "Hunt"}
        </button>
      </div>

      <div className="search-meta">
        {reading && (
          <>
            <span className="type-chip">{reading.ioc_type}</span>
            {refanged && (
              <span className="refang-note mono-value">refanged to {reading.indicator}</span>
            )}
          </>
        )}
        {unreadable && (
          <span className="type-chip" data-unknown="true">
            unrecognised
          </span>
        )}
      </div>
    </form>
  );
}
