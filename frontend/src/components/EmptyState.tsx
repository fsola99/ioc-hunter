interface Props {
  onPick: (indicator: string) => void;
}

const SAMPLES: [string, string][] = [
  ["md5", "44d88612fea8a8f36de82e1278abb02f"],
  ["ipv4", "8.8.8.8"],
  ["domain", "example[.]com"],
  ["url", "hxxps://example.com/login"],
];

/** The opening screen: what to paste, and something to paste right now. */
export function EmptyState({ onPick }: Props) {
  return (
    <section className="empty">
      <h2>Paste an indicator to see who has flagged it, and why.</h2>
      <p>
        Hashes, IP addresses, domains and URLs all resolve to the same report shape, so a triage
        reads the same way whatever landed in the ticket. Defanged indicators are read as written —
        <code> evil[.]com</code> and <code>hxxp://</code> need no cleaning up first.
      </p>

      <div className="samples">
        {SAMPLES.map(([type, value]) => (
          <button className="sample" type="button" key={value} onClick={() => onPick(value)}>
            <span className="sample-type">{type}</span>
            <span className="sample-value mono-value">{value}</span>
          </button>
        ))}
      </div>
    </section>
  );
}
