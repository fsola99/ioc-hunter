import type { VendorVerdict } from "../types";

interface Props {
  vendors: VendorVerdict[];
}

const VERDICT_BY_CATEGORY: Record<string, string> = {
  malicious: "malicious",
  suspicious: "suspicious",
  harmless: "harmless",
};

/** Every engine's call, most severe first. */
export function VendorTable({ vendors }: Props) {
  const flagging = vendors.filter(
    (vendor) => vendor.category === "malicious" || vendor.category === "suspicious",
  );

  if (vendors.length === 0) {
    return <p className="muted">This provider returned no per-engine results for this indicator.</p>;
  }

  return (
    <div className="table-scroll">
      <table>
        <caption className="eyebrow" style={{ textAlign: "left", paddingBottom: "0.75rem" }}>
          {flagging.length} of {vendors.length} engines flagged this indicator
        </caption>
        <thead>
          <tr>
            <th scope="col">Engine</th>
            <th scope="col">Category</th>
            <th scope="col">Detection</th>
            <th scope="col">Updated</th>
          </tr>
        </thead>
        <tbody>
          {vendors.map((vendor) => (
            <tr key={vendor.engine}>
              <td className="value">{vendor.engine}</td>
              <td>
                <span className="dot" data-verdict={VERDICT_BY_CATEGORY[vendor.category] ?? ""}>
                  {vendor.category}
                </span>
              </td>
              <td className="value">{vendor.result ?? "—"}</td>
              <td>{vendor.updated ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
