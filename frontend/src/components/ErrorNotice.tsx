import { ApiError } from "../api";

interface Props {
  error: ApiError;
}

function heading(error: ApiError): string {
  if (error.isNotFound) return "no record";
  if (error.isQuota) return "quota exhausted";
  if (error.isUnconfigured) return "not configured";
  return "lookup failed";
}

function guidance(error: ApiError): string | null {
  if (error.isNotFound) {
    return "Nothing has been submitted for analysis under this indicator. Absence of a record is not a clean verdict.";
  }
  if (error.isQuota) {
    return "Wait a minute and try again. Repeat lookups of the same indicator are served from cache and cost nothing.";
  }
  if (error.isUnconfigured) {
    return "Add your key to the .env file at the project root, then restart the backend.";
  }
  return null;
}

/** A failed lookup, explained in terms of what to do next. */
export function ErrorNotice({ error }: Props) {
  const advice = guidance(error);

  return (
    <section
      className="notice"
      data-verdict={error.isNotFound ? "unknown" : "suspicious"}
      role="alert"
    >
      <h2>{heading(error)}</h2>
      <p>{error.message}</p>
      {advice && <p>{advice}</p>}
    </section>
  );
}
