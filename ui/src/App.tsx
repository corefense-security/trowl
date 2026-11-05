import {
  Binary as BinaryIcon, ChevronRight, Cpu, HardDrive, LayoutDashboard, Moon, Network,
  ShieldAlert, Sun, Upload,
} from "lucide-react";
import { Fragment, useEffect, useState, type ReactNode } from "react";
import type { Report } from "./types";
import { Logo } from "./ui";
import Binaries from "./views/Binaries";
import Filesystems from "./views/Filesystems";
import Kernel from "./views/Kernel";
import Modules from "./views/Modules";
import Cves from "./views/Cves";
import Overview from "./views/Overview";
import SbomGraph from "./views/SbomGraph";

export type Route = "overview" | "filesystems" | "kernel" | "modules" | "binaries" | "sbom" | "cves";
type Theme = "light" | "dark";

function readRoute(): Route {
  const r = window.location.hash.replace(/^#\/?/, "").split("?")[0];
  return (["overview", "filesystems", "kernel", "modules", "binaries", "sbom", "cves"] as Route[]).includes(r as Route)
    ? (r as Route) : "overview";
}

function loadTheme(): Theme {
  // Saved choice first; otherwise start from the OS preference.
  try {
    const saved = localStorage.getItem("trowl-theme");
    if (saved === "light" || saved === "dark") return saved;
  } catch { /* storage unavailable */ }
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

/** Seconds as "14m 52s", or "45s" under a minute. */
function duration(s: number) {
  const n = Math.round(s);
  return n < 60 ? `${n}s` : `${Math.floor(n / 60)}m ${n % 60}s`;
}

export default function App({ initial, error }: { initial: Report | null; error?: string }) {
  const [report, setReport] = useState<Report | null>(initial);
  const [route, setRoute] = useState<Route>(readRoute);
  const [hash, setHash] = useState(window.location.hash);
  const [theme, setTheme] = useState<Theme>(loadTheme);
  // Sidebar groups (Kernel) start collapsed; one is open while one of its pages is showing.
  const [openGroup, setOpenGroup] = useState<string | null>(null);

  useEffect(() => {
    const on = () => { setRoute(readRoute()); setHash(window.location.hash); };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute("data-theme", theme);
    try { localStorage.setItem("trowl-theme", theme); } catch { /* storage unavailable */ }
  }, [theme]);

  const go = (r: Route, params?: Record<string, string>) => {
    window.location.hash = `/${r}` + (params ? `?${new URLSearchParams(params)}` : "");
  };

  if (!report) return <Loader onLoad={setReport} error={error} />;

  const cves = report.cves;
  const hasSecrets = report.findings.some((f) => f.check.startsWith("secrets."));
  const binaries = report.binaries.filter((b) => b.kind === "executable" || b.kind === "library").length;
  // off: the sidebar note for a page with nothing to show, and why: its tooltip.
  const nav: { id: Route; label: string; icon: ReactNode; badge?: number; group?: string; off?: string; why?: string }[] = [
    { id: "overview", label: "Overview", icon: <LayoutDashboard size={17} /> },
    { id: "filesystems", label: "Filesystems", icon: <HardDrive size={17} />, badge: report.fstab.length || undefined,
      off: report.fstab.length || hasSecrets ? undefined : "Not found", why: "No /etc/fstab and no secrets found in the image" },
    { id: "kernel", label: "Config", group: "Kernel", icon: null, badge: report.kernel?.entries.filter((e) => e.status === "fail" || e.status === "missing").length || undefined,
      off: report.kernel?.source ? undefined : "Not found",
      why: "No kernel config in the image: no /boot/config-*, and no embedded config (CONFIG_IKCONFIG). Pass one with --kernel-config or --kernel-src." },
    { id: "modules", label: "Modules", group: "Kernel", icon: null, badge: report.kernel?.modules?.items.length,
      off: report.kernel?.modules?.items.length ? undefined : "Not found", why: "No kernel modules found in the image" },
    { id: "binaries", label: "Binary", icon: <BinaryIcon size={17} />, badge: binaries,
      off: binaries ? undefined : "Not found", why: "No executables or libraries found in the image" },
    { id: "sbom", label: "SBOM Analysis", icon: <Network size={17} />, badge: report.sbom?.graph.nodes.length,
      off: report.sbom ? undefined : "Not provided", why: "Scan with --sbom to compare an SBOM against the image" },
    { id: "cves", label: "CVEs", icon: <ShieldAlert size={17} />, badge: cves?.summary.unpatched_shipped,
      off: cves ? undefined : "Not found", why: "No SBOM, package database or kernel version to match CVEs against" },
  ];
  const current = nav.find((n) => n.id === route && !n.off) ?? nav[0];
  // openGroup: a group name when the user opened it, "" when they closed the group they're in.
  const groupOpen = (g?: string) => !!g && (openGroup === g || (openGroup === null && current.group === g));
  const imageName = report.image.path.split("/").pop() || report.image.path;

  const nextTheme: Theme = theme === "dark" ? "light" : "dark";

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><Logo size={20} /></div>
          <div>
            <div className="brand-name">Trowl</div>
            <div className="brand-ver">v{report.tool.version}</div>
          </div>
        </div>
        <div className="nav-label">Analysis</div>
        {nav.map((n, i) => (
          <Fragment key={n.id}>
            {n.group && nav[i - 1]?.group !== n.group && (
              <button className={`nav-item nav-group ${current.group === n.group ? "open" : ""} ${nav.every((x) => x.group !== n.group || x.off) ? "dim" : ""}`} aria-expanded={groupOpen(n.group)}
                onClick={() => setOpenGroup(groupOpen(n.group) ? (current.group === n.group ? "" : null) : n.group!)}>
                <Cpu size={17} /><span>{n.group}</span>
                <ChevronRight size={14} className={`nav-chev ${groupOpen(n.group) ? "down" : ""}`} />
              </button>
            )}
            {(!n.group || groupOpen(n.group)) && (
            <button className={`nav-item ${n.group ? "nav-sub" : ""} ${current.id === n.id ? "active" : ""}`} disabled={!!n.off} title={n.off ? n.why : undefined} onClick={() => go(n.id)}>
              {n.icon}
              <span>{n.label}{n.off && <small className="nav-na">{n.off}</small>}</span>
              {n.badge !== undefined && <span className="badge num">{n.badge}</span>}
            </button>
            )}
          </Fragment>
        ))}
      </aside>

      <div className="main">
        <header className="topbar">
          <span className="tb-name" title={report.image.path}>{imageName}</span>
          {report.summary.scanned_at && <span className="tb-meta num">{report.summary.scanned_at.slice(0, 16).replace("T", " ")} UTC</span>}
          <span className="tb-meta num">Scan time: {duration(report.summary.duration_s)}</span>
          <span className="spacer" />
          <button className="icon-btn" onClick={() => setTheme(nextTheme)} title={`Switch to ${nextTheme} theme`} aria-label={`Switch to ${nextTheme} theme`}>
            {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
          </button>
        </header>
        <div className={`content ${current.id === "sbom" ? "flush" : ""}`}>
          {current.id === "overview" && <Overview r={report} go={go} />}
          {current.id === "filesystems" && <Filesystems r={report} />}
          {current.id === "kernel" && <Kernel r={report} />}
          {current.id === "modules" && <Modules r={report} />}
          {current.id === "binaries" && <Binaries key={hash} binaries={report.binaries} params={new URLSearchParams(hash.split("?")[1] ?? "")} />}
          {current.id === "sbom" && report.sbom && (
            <SbomGraph key={hash} graph={report.sbom.graph} params={new URLSearchParams(hash.split("?")[1] ?? "")} />
          )}
          {current.id === "cves" && cves && (
            <Cves key={hash} section={cves} params={new URLSearchParams(hash.split("?")[1] ?? "")} />
          )}
        </div>
      </div>
    </div>
  );
}

/** Tells a Trowl report from any other JSON, such as the SBOM next to it. */
function isReport(x: Partial<Report> | null): x is Report {
  return x?.tool?.name === "trowl" && Array.isArray(x.findings) && Array.isArray(x.fstab) && !!x.summary;
}

function Loader({ onLoad, error }: { onLoad: (r: Report) => void; error?: string }) {
  const [err, setErr] = useState(error ?? "");
  return (
    <div className="loader">
      <div className="brand">
        <div className="brand-mark"><Logo size={20} /></div>
        <div className="brand-name">Trowl</div>
      </div>
      <div className="card">
        <p style={{ marginTop: 0 }}>Open a <code>report.json</code> produced by <code>trowl scan</code>.</p>
        <label className="btn">
          <Upload size={15} /> Choose report.json
          <input
            type="file" accept=".json,application/json" hidden
            onChange={async (e) => {
              const f = e.target.files?.[0];
              if (!f) return;
              try {
                const data = JSON.parse(await f.text());
                if (isReport(data)) onLoad(data);
                else setErr("That isn't a Trowl report.json.");
              } catch (x) { setErr(String(x)); }
            }}
          />
        </label>
        {err && <p className="no">{err}</p>}
      </div>
    </div>
  );
}
