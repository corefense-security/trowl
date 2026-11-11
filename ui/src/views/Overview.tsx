import { ChevronRight, HardDrive, KeyRound, UserCog, ShieldAlert, Sparkles } from "lucide-react";
import { useMemo, type ReactNode } from "react";
import type { Route } from "../App";
import type { Report } from "../types";
import { Card, CoverageDonut, type CoverageRow } from "../ui";

/** A headline count. By default it is red when any need attention and green when none do. */
function Stat({ icon, label, value, tone = value > 0 ? "stat-bad" : "stat-ok", foot, onClick }: {
  icon: ReactNode; label: string; value: number; tone?: string; foot: ReactNode; onClick: () => void;
}) {
  return (
    <button className="stat" onClick={onClick}>
      <span className="stat-l">{icon}{label}<ChevronRight size={14} className="stat-go" /></span>
      <span className={`stat-v num ${tone}`}>{value}</span>
      <span className="stat-f">{foot}</span>
    </button>
  );
}

/** The Share layout with no data behind it (a grey bar and dashes), for a scan without an SBOM. */
function ShareOff({ title, labels }: { title: string; labels: string[] }) {
  return (
    <div className="share share-off">
      <div className="share-top">
        <div className="share-t">{title}</div>
        <div className="share-n"><b className="num">–</b></div>
        <div className="share-bar" aria-hidden><i style={{ flex: 1 }} /></div>
        <div className="share-legend">
          {labels.map((l) => <span key={l}><i className="swatch" />{l} <b className="num">–</b></span>)}
        </div>
      </div>
    </div>
  );
}

/** One number out of a whole. A segmented bar shows the number first, then what makes up the
 *  rest, with a line saying what it means. */
function Share({ title, n, of, nLabel, rest, note, color = "var(--violet)", split }: {
  title: string; n: number; of: number; nLabel: string; color?: string;
  rest: { label: string; value: number; color: string }[]; note: ReactNode;
  /** The headline number in several segments, in place of the single nLabel one. */
  split?: { label: string; value: number; color: string }[];
}) {
  const parts = [...(split ?? [{ label: nLabel, value: n, color }]), ...rest].filter((x) => x.value > 0);
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

/** A summary line, with kernel options, paths, mount flags and CVE ids set in the code font. The
 *  model often drops the CONFIG_ prefix, so names from the kernel check get it back, as on the
 *  Kernel page. */
function Point({ text, options }: { text: string; options: Set<string> }) {
  return <>{text.split(/(CONFIG_\w+(?:=\w+)?|CVE-\d+-\d+|(?<![\w/])\/[\w.-]+(?:\/[\w.-]+)*\w|(?<![\w/-])(?:ro|nosuid|nodev|noexec|hidepid(?:=\w+(?:\/\w+)*)?)(?![\w-]))/).map((s, i) =>
    i % 2 ? <code key={i}>{s}</code> : s.split(/\b([A-Z][A-Z0-9_]+)\b/).map((w, j) =>
      j % 2 && options.has(w) ? <code key={`${i}-${j}`}>CONFIG_{w}</code> : w))}</>;
}

export default function Overview({ r, go }: { r: Report; go: (r: Route, p?: Record<string, string>) => void }) {
  const judged = useMemo(() => r.binaries.filter((b) => b.kind === "executable" || b.kind === "library"), [r]);
  const execs = judged.filter((b) => b.kind === "executable");
  const secrets = r.findings.filter((f) => f.check.startsWith("secrets."));
  const mounts = r.findings.filter((f) => f.check === "fstab.mount-options");
  const options = useMemo(() => new Set(r.kernel?.entries.map((e) => e.option)), [r]);

  const cf = judged.filter((b) => b.cf_protection);
  const cfKey = cf.some((b) => b.cf_protection && "ibt" in b.cf_protection) ? "ibt" : "bti";
  const full = judged.filter((b) => b.relro === "full").length;
  const partial = judged.filter((b) => b.relro === "partial").length;
  // A stripped static binary has no symbols to judge its canary by.
  const symbols = judged.filter((b) => !b.no_symbols);
  const coverage: CoverageRow[] = [
    { label: "NX stack", ok: judged.filter((b) => b.nx).length, total: judged.length },
  ];
  if (cf.length) {
    coverage.push({ label: cfKey === "ibt" ? "CET IBT" : "BTI", ok: cf.filter((b) => b.cf_protection?.[cfKey]).length, total: cf.length });
  }
  coverage.push(
    { label: "RELRO", ok: full, total: judged.length, parts: [
      { label: "Full", n: full, of: full + partial }, { label: "Partial", n: partial, of: full + partial }] },
    { label: "Stack canary", ok: symbols.filter((b) => b.canary).length, total: symbols.length },
    { label: "PIE", ok: execs.filter((b) => b.pie).length, total: execs.length },
  );

  const sbom = r.sbom;
  const sc = sbom?.status_counts ?? {};
  const cves = r.cves;
  // A CVE is off the device only when none of the packages that carry it ship.
  // CVEs whose code doesn't reach the device: on build-time components, or kernel CVEs the
  // kernel tree cleared (module not shipped, or code the config leaves out).
  const offDevice = cves?.rows.filter((x) => x.shipped === "build" || x.shipped === "no") ?? [];
  const cleared = (why: string) => cves?.rows.filter((x) => x.kernel &&
    x.carriers.some((c) => c.kernel && c.assessment?.status === "not_affected" && c.assessment.justification === why)).length ?? 0;
  const moduleOff = cleared("component_not_present"), notCompiled = cleared("vulnerable_code_not_present");
  const away = offDevice.length + moduleOff + notCompiled;
  // A normal image has setuid root binaries, so the tile only turns amber for a weakly built one.
  const suid = execs.filter((b) => b.uid === 0 && ((b.mode ?? 0) & 0o4000) !== 0);
  const weak = suid.filter((b) => !b.pie || !b.nx || b.relro !== "full" || (!b.canary && !b.no_symbols)).length;

  // "recipe" is the report's role for a build component. That is anything the SBOM says generates
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
            {r.overview.points.map((p) => <li key={p.topic}><Point text={p.text} options={options} /></li>)}
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
        <Stat icon={<KeyRound size={15} />} label="Secrets" value={secrets.length} onClick={() => go("filesystems")}
          foot={secrets.length ? "keys or tokens in the image" : "no keys or tokens found"} />
        <Stat icon={<HardDrive size={15} />} label="Insecure mounts" value={mounts.length} onClick={() => go("filesystems")}
          foot={r.fstab.length ? (mounts.length ? "missing a secure mount flag" : "all carry the secure flags") : "no /etc/fstab in the image"} />
        {judged.some((b) => b.mode !== undefined) && (
          <Stat icon={<UserCog size={15} />} label="Setuid root" value={suid.length} tone={weak ? "stat-warn" : "stat-plain"}
            onClick={() => go("binaries", { setuid: "1" })}
            foot={weak ? `${weak} missing hardening` : suid.length ? "run as root for any user" : "none in the image"} />
        )}
      </section>

      <div className="ov-main">
        {!sbom ? (
          <Card title="SBOM vs Image" className="sbom-card flexcol">
            <p className="share-none">No SBOM provided. Scan with <code>--sbom</code> to compare it against the image.</p>
            <div className="shares">
              <ShareOff title="Source components in SBOM" labels={["Ship packages", "Build-time only", "Packages not installed", "Unknown"]} />
              <ShareOff title="Packages in SBOM" labels={["Files match", "Changed after build", "Files missing"]} />
              <ShareOff title="CVEs not in image" labels={["Not in image", "On installed packages"]} />
            </div>
          </Card>
        ) : (
          <Card title="SBOM vs Image" className="sbom-card flexcol">
            <div className="shares">
              <Share title="Source components in SBOM" n={comp.ship} of={compTotal} nLabel="Ship packages"
                rest={[{ label: "Build-time only", value: comp.build, color: "var(--neutral)" },
                  { label: "Packages not installed", value: comp.gone, color: "var(--violet-soft)" },
                  { label: "Unknown", value: comp.unknown, color: "var(--ink-2)" }]}
                note={<>Only components with installed packages that reach the image. Build-time dependencies don't ship.{" "}
                  <button className="share-link" onClick={() => go("sbom", { role: "recipe", status: "present", view: "table" })}>
                    Show them <ChevronRight size={13} /></button></>} />
              <Share title="Packages in SBOM" n={pk.match} of={declared} nLabel="Files match"
                rest={[{ label: "Changed after build", value: pk.changed, color: "var(--warning)" },
                  { label: "Files missing", value: pk.partial + pk.absent, color: "var(--critical)" }]}
                note={<>{pk.changed + pk.partial + pk.absent === 0 ? <>Every installed file has the hash the SBOM recorded.</>
                  : <>Installed files checked against SBOM by path and SHA-256.{changedPaths.length > 0 && <> {changedPaths.length} file{changedPaths.length === 1 ? "" : "s"} changed
                    across {pk.changed} package{pk.changed === 1 ? "" : "s"}: {changedPaths.slice(0, 3).map((p, i) =>
                    <span key={p}>{i > 0 && ", "}<code>{p}</code></span>)}{changedPaths.length > 3 && ` +${changedPaths.length - 3} more`}.</>}</>}{" "}
                  <button className="share-link" onClick={() => go("sbom", { role: "package", status: "present" })}>
                    Show them <ChevronRight size={13} /></button></>} />
              {cves && (
                <Share title="CVEs not in image" n={away} of={cves.rows.length} nLabel="Not in image"
                  split={[{ label: "Build time", value: offDevice.length, color: "var(--good)" },
                    { label: "Kernel module not shipped", value: moduleOff, color: "var(--violet)" },
                    { label: "Kernel code not compiled", value: notCompiled, color: "var(--violet-soft)" }]}
                  rest={[{ label: "Potentially in image", value: cves.rows.length - away, color: "var(--neutral)" }]}
                  note={<>Vulnerable code in build tools, or kernel code that's not compiled or whose module doesn't ship.{!cves.sources.kernel_vex && <> Scan with <code className="cmd">--kernel-tree</code> to
                    clear kernel CVEs too.</>}{" "}
                    <button className="share-link" onClick={() => go("cves", { status: "all", shipped: "no" })}>
                      Show them <ChevronRight size={13} /></button></>} />
              )}
            </div>
          </Card>
        )}
      </div>

      <Card title="Hardening coverage" className="ov-rail"
        right={<button className="btn" onClick={() => go("binaries")}>Matrix <ChevronRight size={14} /></button>}>
        <p className="rail-sub">% of shipped binaries that are compiler hardened</p>
        <CoverageDonut rows={coverage} center={judged.length} centerLabel="binaries" />
        <div className="muted rail-note">Share of {judged.length} executables and libraries with each protection</div>
      </Card>
    </div>
  );
}
