import { ChevronRight, HardDrive, KeyRound, Puzzle, ShieldAlert, Sparkles } from "lucide-react";
import { useMemo, type ReactNode } from "react";
import type { Route } from "../App";
import type { Report } from "../types";
import { Card, CoverageDonut, type CoverageRow } from "../ui";
import { cveSources } from "./Cves";

/** A headline count. `bad` is how many of it need attention: red when any do, green when none. */
function Stat({ icon, label, value, bad, foot, onClick }: {
  icon: ReactNode; label: string; value: number; bad?: number; foot: ReactNode; onClick: () => void;
}) {
  const tone = (bad ?? value) > 0 ? "stat-bad" : "stat-ok";
  return (
    <button className="stat" onClick={onClick}>
      <span className="stat-l">{icon}{label}<ChevronRight size={14} className="stat-go" /></span>
      <span className={`stat-v num ${tone}`}>{value}</span>
      <span className="stat-f">{foot}</span>
    </button>
  );
}

/** One number out of a whole: a segmented bar (the number first, then what makes up the rest)
 *  and a line saying what it means. */
function Share({ title, n, of, nLabel, rest, note, color = "var(--violet)" }: {
  title: string; n: number; of: number; nLabel: string; color?: string;
  rest: { label: string; value: number; color: string }[]; note: ReactNode;
}) {
  const parts = [{ label: nLabel, value: n, color }, ...rest].filter((x) => x.value > 0);
  return (
    <div className="share">
      <div className="share-top">
        <div className="share-t">{title}</div>
        <div className="share-n"><b className="num">{n}</b><span> of {of}</span></div>
        <div className="share-bar" role="img" aria-label={parts.map((x) => `${x.label} ${x.value}`).join(", ")}>
          {parts.map((x) => <i key={x.label} style={{ flex: x.value, background: x.color }} title={`${x.label}: ${x.value}`} />)}
        </div>
        <div className="share-legend">
          {parts.map((x) => (
            <span key={x.label}><i className="swatch" style={{ background: x.color }} />{x.label} <b className="num">{x.value}</b></span>
          ))}
        </div>
      </div>
      <p className="share-note">{note}</p>
    </div>
  );
}

export default function Overview({ r, go }: { r: Report; go: (r: Route, p?: Record<string, string>) => void }) {
  const judged = useMemo(() => r.binaries.filter((b) => b.kind === "executable" || b.kind === "library"), [r]);
  const execs = judged.filter((b) => b.kind === "executable");
  const secrets = r.findings.filter((f) => f.check.startsWith("secrets."));
  const mounts = r.findings.filter((f) => f.check === "fstab.mount-options");

  const cf = judged.filter((b) => b.cf_protection);
  const cfKey = cf.some((b) => b.cf_protection && "ibt" in b.cf_protection) ? "ibt" : "bti";
  const full = judged.filter((b) => b.relro === "full").length;
  const partial = judged.filter((b) => b.relro === "partial").length;
  const coverage: CoverageRow[] = [
    { label: "NX stack", ok: judged.filter((b) => b.nx).length, total: judged.length },
  ];
  if (cf.length) {
    coverage.push({ label: cfKey === "ibt" ? "CET IBT" : "BTI", ok: cf.filter((b) => b.cf_protection?.[cfKey]).length, total: cf.length });
  }
  coverage.push(
    { label: "RELRO", ok: full, total: judged.length, parts: [
      { label: "Full", n: full, of: full + partial }, { label: "Partial", n: partial, of: full + partial }] },
    { label: "Stack canary", ok: judged.filter((b) => b.canary).length, total: judged.length },
    { label: "PIE", ok: execs.filter((b) => b.pie).length, total: execs.length },
  );

  const sbom = r.sbom;
  const sc = sbom?.status_counts ?? {};
  const cves = sbom?.cves;
  // A CVE is off the device only when none of the packages that carry it ship.
  const offDevice = cves?.rows.filter((x) => x.shipped === "build" || x.shipped === "no") ?? [];
  const offOpen = offDevice.filter((x) => x.status === "unpatched").length;
  const src = cveSources(cves?.rows ?? []);
  const mods = r.kernel?.modules?.items;
  const unsigned = mods?.filter((m) => !m.signed).length ?? 0;

  // "recipe" is the report's role for a build component: anything the SBOM says generates
  // binary packages (a Yocto recipe, a Buildroot package, a source package elsewhere).
  const comp = { ship: sc["recipe:present"] ?? 0, build: sc["recipe:build-only"] ?? 0,
    gone: sc["recipe:absent"] ?? 0, unknown: sc["recipe:unknown"] ?? 0 };
  const compTotal = comp.ship + comp.build + comp.gone + comp.unknown;
  const pk = { match: sc["package:present"] ?? 0, changed: sc["package:modified"] ?? 0,
    partial: sc["package:partial"] ?? 0, absent: sc["package:absent"] ?? 0 };
  const declared = pk.match + pk.changed + pk.partial + pk.absent;
  const changedPaths = (sbom?.graph.nodes ?? [])
    .filter((n) => n.role === "package" && n.status === "modified")
    .flatMap((n) => n.files?.modified_paths ?? []);

  return (
    <div className={`ov ${r.overview ? "has-summary" : ""}`}>
      {r.overview && (
        <section className="card ov-summary">
          <div className="ov-summary-h"><Sparkles size={16} className="ov-spark" /> Key summary</div>
          <ul className="ov-points">
            {r.overview.points.map((p) => <li key={p.topic}>{p.text}</li>)}
          </ul>
          <div className="ov-summary-src">Generated by {r.overview.label} locally</div>
        </section>
      )}
      <section className="card statbar">
        {cves && (
          <Stat icon={<ShieldAlert size={15} />} label="Unpatched CVEs" value={cves.summary.unpatched_shipped}
            onClick={() => go("cves", { status: "unpatched" })}
            foot={cves.sources.kev ? `${cves.summary.kev} in CISA KEV` : "CISA KEV not checked"} />
        )}
        {mods && mods.length > 0 && (
          <Stat icon={<Puzzle size={15} />} label="Installed Modules" value={mods.length} bad={unsigned} onClick={() => go("modules")}
            foot={unsigned === mods.length ? "all are unsigned" : unsigned === 0 ? "all are signed" : `${unsigned} are unsigned`} />
        )}
        <Stat icon={<KeyRound size={15} />} label="Secrets" value={secrets.length} onClick={() => go("filesystems")}
          foot={secrets.length ? "keys or tokens in the image" : "no keys or tokens found"} />
        <Stat icon={<HardDrive size={15} />} label="Insecure mounts" value={mounts.length} onClick={() => go("filesystems")}
          foot={r.fstab.length ? (mounts.length ? "missing a secure mount flag" : "all carry the secure flags") : "no /etc/fstab in the image"} />
      </section>

      <div className="ov-main">
        {sbom && (
          <Card title="SBOM vs Image" className="sbom-card flexcol">
            <div className="shares">
              <Share title="Source components in SBOM" n={comp.ship} of={compTotal} nLabel="Ship packages"
                rest={[{ label: "Build-time only", value: comp.build, color: "var(--neutral)" },
                  { label: "Packages not installed", value: comp.gone, color: "var(--violet-soft)" },
                  { label: "Unknown", value: comp.unknown, color: "var(--ink-2)" }]}
                note={<>Each component in the SBOM builds one or more packages, and only installed packages ship. Build-time components
                  never ship, so their CVEs don't apply to it.{" "}
                  <button className="share-link" onClick={() => go("sbom", { role: "recipe", status: "present", view: "table" })}>
                    Show them <ChevronRight size={13} /></button></>} />
              <Share title="Packages in SBOM" n={pk.match} of={declared} nLabel="Files match"
                rest={[{ label: "Changed after build", value: pk.changed, color: "var(--warning)" },
                  { label: "Files missing", value: pk.partial + pk.absent, color: "var(--critical)" }]}
                note={<>{pk.changed + pk.partial + pk.absent === 0 ? <>Every installed file has the hash the SBOM recorded.</>
                  : <>Compared by path and SHA-256.{changedPaths.length > 0 && <> {changedPaths.length} file{changedPaths.length === 1 ? "" : "s"} changed
                    across {pk.changed} package{pk.changed === 1 ? "" : "s"}: {changedPaths.slice(0, 3).map((p, i) =>
                    <span key={p}>{i > 0 && ", "}<code>{p}</code></span>)}{changedPaths.length > 3 && ` +${changedPaths.length - 3} more`}.</>}</>}{" "}
                  <button className="share-link" onClick={() => go("sbom", { role: "package", status: "present" })}>
                    Show them <ChevronRight size={13} /></button></>} />
              {cves && (
                <Share title="CVEs not in image" n={offDevice.length} of={cves.rows.length} nLabel="Not in image" color="var(--good)"
                  rest={[{ label: "On installed packages", value: cves.rows.length - offDevice.length, color: "var(--neutral)" }]}
                  note={<>No package carrying these CVEs is installed, so they can't affect the device
                    {offOpen ? <>; {offOpen} are still unpatched in the SBOM</> : ""}. Of the {src.total.toLocaleString()} on installed
                    packages, {src.sbom.toLocaleString()} are listed in the SBOM and {src.matched.toLocaleString()} were found by matching package
                    versions against NVD and the kernel CNA.{" "}
                    <button className="share-link" onClick={() => go("cves", { status: "all", shipped: "no" })}>
                      Show them <ChevronRight size={13} /></button></>} />
              )}
            </div>
          </Card>
        )}
      </div>

      <Card title="Hardening coverage" className="ov-rail"
        right={<button className="btn" onClick={() => go("binaries")}>Matrix <ChevronRight size={14} /></button>}>
        <CoverageDonut rows={coverage} center={judged.length} centerLabel="binaries" />
        <div className="muted rail-note">Share of {judged.length} executables and libraries with each protection</div>
      </Card>
    </div>
  );
}
