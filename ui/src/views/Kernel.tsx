import { useMemo } from "react";
import { ShieldCheck, Unlock } from "lucide-react";
import type { KernelEntry, Report } from "../types";
import { PageHead, usePage } from "../ui";

// An option missing from the config counts as a fail, since the protection isn't there either
// way. The row's note still says why it is absent (dependencies off, or no compiler support).
type Shown = "pass" | "fail" | "accepted" | "na";
const shownStatus = (s: KernelEntry["status"]): Shown => (s === "missing" ? "fail" : s);

const STATUS: Record<Shown, { label: string; color: string }> = {
  pass: { label: "Pass", color: "var(--good)" },
  fail: { label: "Fail", color: "var(--critical)" },
  na: { label: "Not applicable", color: "var(--neutral)" },
  accepted: { label: "Accepted", color: "var(--accent)" },
};
const SUBSYSTEM: Record<string, string> = { security: "Security", fs: "Filesystems", mm: "Memory management", net: "Networking", module: "Modules", team: "Team policy" };

function show(v: string | number | { min: number } | null) {
  if (v === null || v === undefined) return <span className="muted">absent</span>;
  if (typeof v === "object") return <>≥ {v.min}</>;
  return v === "n" ? "not set" : String(v);
}

/** Enabling an attack-surface option increases attack surface. Enabling a hardening option increases security. */
const EFFECT = {
  attack_surface: { label: "Increases attack surface", icon: <Unlock size={14} />, cls: "eff-surface" },
  harden: { label: "Increases security", icon: <ShieldCheck size={14} />, cls: "eff-secure" },
};
const ORDER: Shown[] = ["fail", "accepted", "pass", "na"];

function Effect({ bucket }: { bucket: KernelEntry["bucket"] }) {
  const e = EFFECT[bucket];
  return <span className={`eff ${e.cls}`} title={`Enabling it: ${e.label.toLowerCase()}`} aria-label={e.label}>{e.icon}</span>;
}

export default function Kernel({ r }: { r: Report }) {
  const k = r.kernel;
  const rows = useMemo(() => [...(k?.entries ?? [])].sort((a, b) => ORDER.indexOf(shownStatus(a.status)) - ORDER.indexOf(shownStatus(b.status)) ||
    a.subsystem.localeCompare(b.subsystem) || a.option.localeCompare(b.option)), [k]);
  const page = usePage(rows);
  if (!k?.source) return null; // the sidebar disables this page
  const file = k.source.path.split("/").pop();

  return (
    <div className="grid">
      <section className="card span-12">
        <PageHead title="Kernel Config"
          note={<>Linux {k.version || "?"} · {k.arch || "unknown arch"} · Read from <code title={k.source.path}>{file}</code>{k.policy && <> · policy <code>{k.policy.split("/").pop()}</code></>}</>}
          />
      </section>
      <section className="card span-12">
        <table className="kt">
          <thead>
            <tr><th>Option</th><th>Subsystem</th><th className="c">Effect</th><th>Recommended</th><th>Observed</th><th>Result</th></tr>
          </thead>
          <tbody ref={page.bodyRef}>
            {page.rows.map((e) => (
              <tr key={e.subsystem + e.option + String(e.expect)}>
                <td>
                  <code>CONFIG_{e.option}</code>
                  <div className="muted kt-why">{e.why}{e.ref && <span className="kt-ref"> · {e.ref}</span>}</div>
                </td>
                <td className="nowrap">{SUBSYSTEM[e.subsystem] ?? e.subsystem}</td>
                <td className="c"><Effect bucket={e.bucket} /></td>
                <td className="nowrap">{show(e.expect)}</td>
                <td className="nowrap">{show(e.actual)}</td>
                <td>
                  <span className="st"><i className="dot" style={{ background: STATUS[shownStatus(e.status)].color }} />{STATUS[shownStatus(e.status)].label}</span>
                  {e.note && <div className="muted kt-why">{e.note}</div>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {page.pager}
      </section>
    </div>
  );
}
