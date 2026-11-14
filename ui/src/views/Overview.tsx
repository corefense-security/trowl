import { ArrowUpRight, Box, ChevronRight, HardDrive, KeyRound, LockKeyhole, UserCog, ShieldAlert, Sparkles, TriangleAlert } from "lucide-react";
import { useMemo, type ReactNode } from "react";
import type { Route } from "../App";
import type { CveRow, Report } from "../types";
import { CoverageBars, Donut, type CoverageRow } from "../ui";

/** A headline count. By default it is red when any need attention and green when none do. */
function Stat({ icon, label, value, tone = value > 0 ? "stat-bad" : "stat-ok", foot, onClick }: {
  icon: ReactNode; label: string; value: number; tone?: string; foot: ReactNode; onClick: () => void;
}) {
  return (
    <button className="stat" onClick={onClick}>
      <span className="stat-l">{icon}{label}<ChevronRight size={14} className="stat-go" /></span>
      <span className={`stat-v num ${tone}`}>{value.toLocaleString()}</span>
      <span className="stat-f">{foot}</span>
    </button>
  );
}

/** A card with an icon and a title. Its arrow opens the page with the detail. */
function OvCard({ icon, title, open, onOpen, className = "", children }: {
  icon: ReactNode; title: string; open: string; onOpen: () => void; className?: string; children: ReactNode;
}) {
  return (
    <section className={`card ov-card ${className}`}>
      <div className="ov-card-h">
        <span className="ov-card-ic">{icon}</span>
        <h2>{title}</h2>
        <button className="icon-btn" title={open} aria-label={open} onClick={onOpen}><ArrowUpRight size={15} /></button>
      </div>
      {children}
    </section>
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

// What each protection does. Shown in the bar tooltips.
const ABOUT: Record<string, string> = {
  "NX stack": "The stack can't run code.",
  "CET IBT": "Indirect jumps must land on a marked target.",
  BTI: "Indirect branches must land on a marked target.",
  RELRO: "The symbol table is read-only once loaded.",
  "Stack canary": "Catches stack overwrites before a function returns.",
  PIE: "Executables load at a random address.",
};

/** The kernel tree verdict on a CVE if it has one. */
const kernelAssessment = (r: CveRow) => r.carriers.find((c) => c.kernel && c.assessment)?.assessment;

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
  const row = (label: string, ok: number, total: number, parts?: CoverageRow["parts"]): CoverageRow =>
    ({ label, ok, total, about: ABOUT[label], parts });
  const coverage: CoverageRow[] = [row("NX stack", judged.filter((b) => b.nx).length, judged.length)];
  if (cf.length) {
    coverage.push(row(cfKey === "ibt" ? "CET IBT" : "BTI", cf.filter((b) => b.cf_protection?.[cfKey]).length, cf.length));
  }
  coverage.push(
    row("RELRO", full, judged.length, [{ label: "Full", n: full }, { label: "Partial", n: partial }]),
    row("Stack canary", symbols.filter((b) => b.canary).length, symbols.length),
    row("PIE", execs.filter((b) => b.pie).length, execs.length),
  );

  // Count the CVEs on the device by status.
  // Kernel CVEs the tree clears are split by reason. Other Not affected ones come from the SBOM.
  const cves = r.cves;
  const t = useMemo(() => {
    const n = { affected: 0, notCompiled: 0, moduleOff: 0, sbomNA: 0, review: 0, fixed: 0,
      disagree: 0, falsePos: 0, falseNeg: 0, disagreeReview: 0 };
    for (const x of cves?.rows ?? []) {
      if (x.shipped === "build" || x.shipped === "no") continue;
      const a = x.kernel ? kernelAssessment(x) : undefined;
      if (x.status === "fixed") n.fixed++;
      else if (x.status === "unpatched") n.affected++;
      else if (x.status === "review" || x.status === "unknown") n.review++;
      else if (a?.status === "not_affected" && a.justification === "vulnerable_code_not_present") n.notCompiled++;
      else if (a?.status === "not_affected" && a.justification === "component_not_present") n.moduleOff++;
      else n.sbomNA++;
      if (a?.defies_sbom) {
        n.disagree++;
        if (a.status === "not_affected") n.falsePos++;
        else if (a.status === "affected") n.falseNeg++;
        else n.disagreeReview++;
      }
    }
    return n;
  }, [cves]);
  const open = t.affected + t.notCompiled + t.moduleOff + t.sbomNA + t.review;
  const slices = [
    { label: "Affected", value: t.affected, color: "var(--serious)" },
    { label: "Kernel code not compiled", value: t.notCompiled, color: "var(--violet)" },
    { label: "Kernel module not shipped", value: t.moduleOff, color: "var(--violet-soft)" },
    { label: "Per SBOM", value: t.sbomNA, color: "color-mix(in srgb, var(--violet) 40%, var(--surface))" },
    { label: "Needs review", value: t.review, color: "var(--neutral)" },
  ].filter((s) => s.value > 0);

  // A normal image has setuid root binaries, so the tile only turns amber for a weakly built one.
  const suid = execs.filter((b) => b.uid === 0 && ((b.mode ?? 0) & 0o4000) !== 0);
  const weak = suid.filter((b) => !b.pie || !b.nx || b.relro !== "full" || (!b.canary && !b.no_symbols)).length;

  const sbom = r.sbom;
  const sc = sbom?.status_counts ?? {};
  const pk = { match: sc["package:present"] ?? 0, changed: sc["package:modified"] ?? 0,
    missing: (sc["package:partial"] ?? 0) + (sc["package:absent"] ?? 0) };
  const installed = pk.match + pk.changed + pk.missing, differ = pk.changed + pk.missing;
  const changedFiles = (sbom?.graph.nodes ?? [])
    .filter((n) => n.role === "package" && n.status === "modified")
    .reduce((k, n) => k + (n.files?.modified_paths?.length ?? 0), 0);

  return (
    <div className="ov">
      {r.overview && (
        <section className="card ov-summary">
          <div className="ov-summary-h"><Sparkles size={16} className="ov-spark" /> Key summary</div>
          <ul className="ov-points">
            {r.overview.points.map((p) => <li key={p.topic}><Point text={p.text} options={options} /></li>)}
          </ul>
          <div className="ov-summary-src">Generated by {r.overview.label}</div>
        </section>
      )}
      <section className="card statbar">
        {cves && (
          <Stat icon={<ShieldAlert size={15} />} label="Affected CVEs" value={cves.summary.unpatched_shipped}
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

      <div className="ov-row">
        <OvCard icon={<ShieldAlert size={16} />} title="CVEs in installed packages" open="Open the CVEs" onOpen={() => go("cves")}>
          {cves && open > 0 ? (
            <Donut slices={slices} center={open.toLocaleString()} centerLabel="Unpatched">
              {!cves.sources.kernel_vex && (
                <p className="dn-hint">Scan with <code className="cmd">--kernel-tree</code> to rule out kernel CVEs</p>
              )}
            </Donut>
          ) : (
            <p className="ov-none">{cves ? "Every CVE on an installed package is fixed." : "No CVE data for this scan."}</p>
          )}
          {t.disagree > 0 && (
            <div className="ov-dg" title="Kernel CVEs where trowl's check of the kernel tree disagrees with the SBOM's VEX status">
              <span className="ov-dg-lead"><TriangleAlert size={14} />{t.disagree} disagree with SBOM</span>
              <span className="ov-dg-split">{[
                t.falsePos && `${t.falsePos} false positive${t.falsePos === 1 ? "" : "s"}`,
                t.falseNeg && `${t.falseNeg} false negative${t.falseNeg === 1 ? "" : "s"}`,
                t.disagreeReview && `${t.disagreeReview} to review`,
              ].filter(Boolean).join(" · ")}</span>
              <button className="share-link" onClick={() => go("cves", { disagree: "1" })}>Details <ChevronRight size={13} /></button>
            </div>
          )}
          {sbom && (
            <div className="ov-pk" title={`Installed files checked against the SBOM by path and SHA-256.${changedFiles ? ` ${changedFiles} file${changedFiles === 1 ? "" : "s"} differ.` : ""}`}>
              <div className="ov-pk-t"><Box size={15} /><span>Installed packages</span></div>
              <div className="ov-pk-r">
                {differ === 0 ? <div className="ov-pk-n"><b className="num ok">All {installed}</b>packages matched by path and SHA-256 checks</div>
                  : <div className="ov-pk-n"><b className="num">{differ}</b>of {installed} {pk.missing ? "differ from the SBOM" : "changed after build"}</div>}
                <button className="share-link" onClick={() => go("sbom", differ && !pk.missing ? { role: "package", status: "modified" } : { role: "package" })}>
                  Show them <ChevronRight size={13} /></button>
              </div>
            </div>
          )}
        </OvCard>

        <OvCard icon={<LockKeyhole size={16} />} title="Hardening coverage" open="Open the hardening matrix" onOpen={() => go("binaries")}>
          <CoverageBars rows={coverage} />
        </OvCard>
      </div>
    </div>
  );
}
