import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import type { Report } from "./types";
// Same faces as the Corefense dashboard, built into the page: a report must not call out.
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "./styles.css";

// The CLI replaces the placeholder in #trowl-report with the report, as plain JSON or as
// "gz:" + base64 gzip. When the page is opened unfilled (dev server, or the bare template),
// the App offers a report.json picker.
async function embeddedReport(): Promise<{ report?: Report; error?: string }> {
  const text = document.getElementById("trowl-report")?.textContent?.trim();
  if (!text || text.startsWith("__TROWL")) return {}; // unfilled template
  try {
    if (!text.startsWith("gz:")) return { report: JSON.parse(text) as Report };
    const bytes = Uint8Array.from(atob(text.slice(3)), (c) => c.charCodeAt(0));
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
    return { report: JSON.parse(await new Response(stream).text()) as Report };
  } catch (e) {
    return { error: `This page's report couldn't be read: ${e}` };
  }
}

/** Shows what went wrong when a page can't draw its data, rather than a blank window. */
class Boundary extends React.Component<{ children: React.ReactNode }, { error?: unknown }> {
  state: { error?: unknown } = {};
  static getDerivedStateFromError(error: unknown) { return { error }; }
  render() {
    if (this.state.error === undefined) return this.props.children;
    return (
      <div className="loader">
        <div className="card">
          <p style={{ marginTop: 0 }}>This page can't show the report: {String(this.state.error)}</p>
          <button className="btn" onClick={() => { window.location.hash = ""; window.location.reload(); }}>Back to Overview</button>
        </div>
      </div>
    );
  }
}

embeddedReport().then(({ report, error }) => {
  createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <Boundary><App initial={report ?? null} error={error} /></Boundary>
    </React.StrictMode>,
  );
});
