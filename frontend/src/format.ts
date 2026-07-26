/** Render a byte count in the largest unit that keeps it readable. */
export function bytes(value: number | null): string {
  if (value === null) return "—";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size < 10 ? 1 : 0)} ${units[unit]}`;
}

/** Render an ISO timestamp as a calendar date. */
export function date(value: string | null): string {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? "—"
    : parsed.toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "2-digit",
      });
}

/** Render an ISO timestamp as a date and time. */
export function dateTime(value: string | null): string {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
}

/** Render an ATT&CK signature severity as a short label. */
export function severity(value: string): string {
  return value.replace("IMPACT_SEVERITY_", "").toLowerCase();
}

/** Shorten a long value for display in a fixed-width slot. */
export function truncate(value: string, max = 46): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}
