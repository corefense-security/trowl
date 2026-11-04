import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import type { Report } from "./types";
import "./styles.css";

// The CLI replaces the placeholder in #trowl-report with the report, as plain JSON or as
// "gz:" + base64 gzip. When the page is opened unfilled (dev server, or the bare template),
// the App offers a report.json picker.
async function embeddedReport(): Promise<Report | null> {
  const text = document.getElementById("trowl-report")?.textContent?.trim();
  if (!text || text.startsWith("__TROWL")) return null; // unfilled template
  try {
    if (!text.startsWith("gz:")) return JSON.parse(text) as Report;
    const bytes = Uint8Array.from(atob(text.slice(3)), (c) => c.charCodeAt(0));
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
    return JSON.parse(await new Response(stream).text()) as Report;
  } catch {
    return null;
  }
}

embeddedReport().then((report) => {
  createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <App initial={report} />
    </React.StrictMode>,
  );
});
