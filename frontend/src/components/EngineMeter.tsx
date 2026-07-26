import { useMemo } from "react";

import type { EngineStats, VendorVerdict } from "../types";

interface Props {
  vendors: VendorVerdict[];
  stats: EngineStats;
}

interface Tick {
  key: string;
  category: string;
  label: string;
}

const ORDER = ["malicious", "suspicious", "timeout", "harmless", "undetected"];

function synthesise(stats: EngineStats): Tick[] {
  const counts: [string, number][] = [
    ["malicious", stats.malicious],
    ["suspicious", stats.suspicious],
    ["timeout", stats.timeout],
    ["harmless", stats.harmless],
    ["undetected", stats.undetected],
  ];
  return counts.flatMap(([category, count]) =>
    Array.from({ length: count }, (_, index) => ({
      key: `${category}-${index}`,
      category,
      label: category,
    })),
  );
}

/**
 * One tick per scanning engine, ordered most severe first.
 *
 * The meter is the vendor table compressed into a single readable line: the
 * width of the coloured band is the detection rate, and each tick names the
 * engine behind it on hover.
 */
export function EngineMeter({ vendors, stats }: Props) {
  const ticks = useMemo<Tick[]>(() => {
    if (vendors.length === 0) return synthesise(stats);
    return [...vendors]
      .sort((a, b) => ORDER.indexOf(a.category) - ORDER.indexOf(b.category))
      .map((vendor) => ({
        key: vendor.engine,
        category: vendor.category,
        label: vendor.result
          ? `${vendor.engine}: ${vendor.result}`
          : `${vendor.engine}: ${vendor.category}`,
      }));
  }, [vendors, stats]);

  if (ticks.length === 0) return null;

  return (
    <>
      <div
        className="meter"
        role="img"
        aria-label={`${stats.malicious + stats.suspicious} of ${ticks.length} engines flagged this indicator`}
      >
        {ticks.map((tick, index) => (
          <span
            key={tick.key}
            className="meter-tick"
            data-category={tick.category}
            title={tick.label}
            style={{ animationDelay: `${Math.min(index * 6, 320)}ms` }}
          />
        ))}
      </div>
      <div className="meter-legend">
        <span>
          <b>{stats.malicious}</b> malicious
        </span>
        <span>
          <b>{stats.suspicious}</b> suspicious
        </span>
        <span>
          <b>{stats.harmless}</b> harmless
        </span>
        <span>
          <b>{stats.undetected}</b> undetected
        </span>
        {stats.timeout > 0 && (
          <span>
            <b>{stats.timeout}</b> timeout
          </span>
        )}
      </div>
    </>
  );
}
