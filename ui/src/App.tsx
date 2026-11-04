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

export default function App({ initial }: { initial: Report | null }) {
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

  if (!report) return <Loader onLoad={setReport} />;

  const nav: { id: Route; label: string; icon: ReactNode; badge?: number; show: boolean; group?: string }[] = [
    { id: "overview", label: "Overview", icon: <LayoutDashboard size={17} />, show: true },
    { id: "filesystems", label: "Filesystems", icon: <HardDrive size={17} />, badge: report.fstab.length || undefined, show: true },
    { id: "kernel", label: "Config", group: "Kernel", icon: null, badge: report.kernel?.entries.filter((e) => e.status === "fail" || e.status === "missing").length || undefined, show: true },
    { id: "modules", label: "Modules", group: "Kernel", icon: null, badge: report.kernel?.modules?.items.length, show: true },
    { id: "binaries", label: "Binary", icon: <BinaryIcon size={17} />, badge: report.binaries.filter((b) => b.kind === "executable" || b.kind === "library").length, show: true },
    { id: "sbom", label: "SBOM", icon: <Network size={17} />, badge: report.sbom?.graph.nodes.length, show: !!report.sbom },
    { id: "cves", label: "CVEs", icon: <ShieldAlert size={17} />, badge: report.sbom?.cves?.summary.unpatched_shipped, show: !!report.sbom?.cves },
  ];
  const current = nav.find((n) => n.id === route && n.show) ?? nav[0];
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
        {nav.filter((n) => n.show).map((n, i, shown) => (
          <Fragment key={n.id}>
            {n.group && shown[i - 1]?.group !== n.group && (
              <button className={`nav-item nav-group ${current.group === n.group ? "open" : ""}`} aria-expanded={groupOpen(n.group)}
                onClick={() => setOpenGroup(groupOpen(n.group) ? (current.group === n.group ? "" : null) : n.group!)}>
                <Cpu size={17} /><span>{n.group}</span>
                <ChevronRight size={14} className={`nav-chev ${groupOpen(n.group) ? "down" : ""}`} />
              </button>
            )}
            {(!n.group || groupOpen(n.group)) && (
            <button className={`nav-item ${n.group ? "nav-sub" : ""} ${current.id === n.id ? "active" : ""}`} onClick={() => go(n.id)}>
              {n.icon}
              <span>{n.label}</span>
              {n.badge !== undefined && <span className="badge num">{n.badge}</span>}
            </button>
            )}
          </Fragment>
        ))}
      </aside>

      <div className="main">
        <header className="topbar">
          <span className="tb-name" title={report.image.path}>{imageName}</span>
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
          {current.id === "binaries" && <Binaries binaries={report.binaries} />}
          {current.id === "sbom" && report.sbom && (
            <SbomGraph key={hash} graph={report.sbom.graph} params={new URLSearchParams(hash.split("?")[1] ?? "")} />
          )}
          {current.id === "cves" && report.sbom?.cves && (
            <Cves key={hash} section={report.sbom.cves} params={new URLSearchParams(hash.split("?")[1] ?? "")} />
          )}
        </div>
      </div>
    </div>
  );
}

function Loader({ onLoad }: { onLoad: (r: Report) => void }) {
  const [err, setErr] = useState("");
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
              try { onLoad(JSON.parse(await f.text())); } catch (x) { setErr(String(x)); }
            }}
          />
        </label>
        {err && <p className="no">{err}</p>}
      </div>
    </div>
  );
}
