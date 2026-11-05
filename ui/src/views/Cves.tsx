import { Check, ExternalLink, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { CveCarrier, CveRow, CveSection, CveStatus } from "../types";
import { Card, Dropdown, SearchBox, Switch, usePage } from "../ui";

const SEV_COLOR: Record<string, string> = {
  critical: "var(--critical)", high: "var(--serious)", medium: "var(--warning)", low: "var(--accent)", none: "var(--neutral)",
};
const SEV_LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", none: "Unscored" };
const STATUS: Record<CveStatus, { label: string; color: string }> = {
  unpatched: { label: "Unpatched", color: "var(--serious)" },
  ignored: { label: "Ignored", color: "var(--neutral)" },
  fixed: { label: "Fixed", color: "var(--good)" },
  unknown: { label: "No status", color: "var(--axis)" },
};
const VECTOR: Record<string, string> = {
  network: "Network", adjacent: "Adjacent network", local: "Local", physical: "Physical", "": "Not specified",
};
const OUTSIDE_NOTE = "Not in the SBOM: found by version match (NVD, kernel CNA), possibly published after the build.";
const BACKPORT_NOTE = "Backport: the fix for this kernel's stable series.";
const LINK: Record<string, string> = { nvd: "NVD", osv: "OSV", cve: "CNA", kernel: "Kernel CNA" };

function StatusLabel({ s }: { s: CveStatus }) {
  return <span className="st"><i className="dot" style={{ background: STATUS[s].color }} />{STATUS[s].label}</span>;
}

function Score({ r }: { r: CveRow }) {
  if (!r.cvss) return <span className="muted">–</span>;
  return <span className="st num"><i className="dot" style={{ background: SEV_COLOR[r.severity] }} />{r.cvss.score.toFixed(1)}</span>;
}

function ShippedCell({ r }: { r: CveRow }) {
  if (r.shipped === "yes") return <Check size={16} className="ink2" aria-label="shipped" />;
  if (r.shipped === "build") return <span className="bt">Build time</span>;
  if (r.shipped === "no") return <span className="muted">Not in image</span>;
  return <span className="muted">–</span>;
}

const NAME_ONLY_NOTE = "SBOM is missing a vendor name, so this matched on the package name alone and may be another product's CVE.";

/** Every carrier matched by name alone; one with a vendor behind it makes the CVE stand. */
const nameOnly = (r: CveRow) => r.carriers.every((c) => c.name_only);

/** Whether a CVE's package may be on the device: an unknown one can't be ruled out. */
const onDevice = (r: CveRow) => r.shipped !== "build" && r.shipped !== "no";

/** Where the CVEs on installed packages come from: listed in the SBOM (with its VEX status), or
 *  found only by matching package versions against NVD and the kernel CNA, as Trivy and Grype do. */
export function cveSources(rows: CveRow[]) {
  const installed = rows.filter(onDevice);
  const sbom = installed.filter((r) => r.carriers.some((c) => c.source !== "version-match")).length;
  return { total: installed.length, sbom, matched: installed.length - sbom };
}

export function SourceNote({ rows, feed, inventory }: { rows: CveRow[]; feed: CveSection["sources"]["version_match"]; inventory?: string }) {
  const s = cveSources(rows);
  if (inventory) {
    return <span title="No SBOM, so there are no Fixed or Ignored statuses: every match shows as Unpatched.">
      No SBOM passed · {inventory === "kernel only" && "kernel CVEs only · "}version matches, backports not checked</span>;
  }
  return (
    <span title={feed ? `Version match: ${feed.source}, updated ${feed.updated.slice(0, 10)}` : undefined}>
      {s.sbom.toLocaleString()} listed in the SBOM · {s.matched.toLocaleString()} by version match (NVD, kernel CNA)
    </span>
  );
}

/** Fixed, Ignored and Unpatched on installed packages, then the Unpatched share zoomed out:
 *  CVSS 7+ and KEV inside it. */
function Attention({ s, rows, sources }: { s: CveSection["summary"]; rows: CveRow[]; sources: CveSection["sources"] }) {
  const kevChecked = !!sources.kev;
  const installed = rows.filter(onDevice);
  const fixed = installed.filter((r) => r.status === "fixed").length;
  const ignored = installed.filter((r) => r.status === "ignored").length;
  const open = s.unpatched_shipped;
  const pct = (n: number) => (open ? (100 * n) / open : 0);
  const openShare = fixed + ignored + open ? (100 * open) / (fixed + ignored + open) : 0;
  const lensX = 1000 - (openShare * 10);
  return (
    <Card title="CVEs in installed packages" hint={<SourceNote rows={rows} feed={sources.version_match} inventory={sources.inventory} />} className="span-7">
      <div className="ig">
        <div className="ig-row"><span><span><b className="num">{sources.inventory ? "–" : fixed.toLocaleString()}</b>{sources.inventory ? "Fixed: needs an SBOM" : "Fixed"}</span>
          {ignored > 0 && <span className="ig-ign"><b className="num">{ignored.toLocaleString()}</b>Ignored</span>}</span><span><b className="num">{open.toLocaleString()}</b>Unpatched</span></div>
        <div className="ig-strip" role="img" aria-label={`${fixed} fixed, ${ignored} ignored, ${open} unpatched`}>
          <i style={{ flex: fixed, background: "var(--good-soft)" }} title={`${fixed.toLocaleString()} fixed`} />
          <i style={{ flex: ignored, background: "var(--neutral)" }} title={`${ignored.toLocaleString()} ignored`} />
          <i style={{ flex: open, background: "var(--serious-soft-2)", minWidth: open ? 4 : 0 }} title={`${open.toLocaleString()} unpatched`} />
        </div>
        <svg className="ig-lens" viewBox="0 0 1000 46" preserveAspectRatio="none" aria-hidden="true">
          <path d={`M${lensX} 0 L1000 0 L1000 46 L0 46 Z`} fill="var(--serious-soft)" />
          <path d={`M${lensX} 0 L0 46 M1000 0 L1000 46`} stroke="var(--serious-soft-2)" vectorEffect="non-scaling-stroke" fill="none" />
        </svg>
        {/* The whole bar is the unpatched set; CVSS 7+ is a band inside it, and KEV a band inside
            that, so each figure reads as part of the one before rather than next to it. */}
        <div className="ig-big" role="img" aria-label={`${open} unpatched, of which ${s.high} have CVSS 7 or more and ${s.kev} are known exploited`}>
          <div className="ig-inner">
            <div className="ig-hi" style={{ width: `${pct(s.high)}%` }} title={`${s.high} with CVSS 7.0 or higher`}>
              {pct(s.high) > 14 && <span>{s.high.toLocaleString()} CVSS 7+</span>}
              {s.kev > 0 && <div className="ig-kev" style={{ width: `max(7px, ${(100 * s.kev) / Math.max(1, s.high)}%)` }} title={`${s.kev} in CISA KEV`} />}
            </div>
          </div>
        </div>
        <div className="ig-stats">
          <div><div className="l"><i className="swatch" style={{ background: "var(--serious-soft-2)" }} />Unpatched</div>
            <div className="n num">{open.toLocaleString()}</div><div className="f">in packages that ship</div></div>
          <div><div className="l"><i className="swatch" style={{ background: "var(--serious)" }} />CVSS 7+</div>
            <div className="n num">{s.high.toLocaleString()}</div><div className="f">high or critical</div></div>
          <div><div className="l"><i className="swatch" style={{ background: "var(--critical)" }} />Known exploited</div>
            <div className="n num">{kevChecked ? s.kev : "–"}</div><div className="f">{kevChecked ? `in CISA KEV` : "KEV not checked (no network)"}</div></div>
        </div>
        {s.unpatched_not_shipped > 0 && (
          <p className="muted" style={{ margin: "12px 0 0", fontSize: 12 }}>
            {s.unpatched_not_shipped} more unpatched CVE(s) are only on packages that don't ship, so they're left out.
          </p>
        )}
      </div>
    </Card>
  );
}

function ByComponent({ s }: { s: CveSection["summary"] }) {
  const sevs = ["critical", "high"];
  const total = (x: Record<string, number | string>) => sevs.reduce((n, k) => n + (Number(x[k]) || 0), 0);
  const rows = s.by_component.filter((x) => total(x) > 0).sort((a, b) => total(b) - total(a) || a.name.localeCompare(b.name));
  const top = rows.slice(0, 8);
  const max = Math.max(1, ...top.map(total));
  return (
    <Card title="Unpatched CVEs by component" className="span-5">
      {top.length === 0 ? <div className="empty">No critical or high unpatched CVEs on shipped packages.</div> : (
        <>
          <div className="sev-legend">
            {sevs.filter((k) => s.severity[k]).map((k) => (
              <span key={k}><i className="swatch" style={{ background: SEV_COLOR[k] }} />{SEV_LABEL[k]} <b className="num">{s.severity[k]}</b></span>
            ))}
            <span className="muted">CVSS, highest of v3 or v4</span>
          </div>
          {top.map((x) => (
            <div className="sr" key={x.name}>
              <code className="ellipsis" title={x.name}>{x.name}</code>
              {/* Proportional to the largest row, with just enough floor that a segment stays visible. */}
              <div className="stack" style={{ width: `max(${(100 * total(x)) / max}%, ${sevs.filter((k) => x[k]).length * 6}px)` }}>
                {sevs.filter((k) => x[k]).map((k) => (
                  <i key={k} style={{ flex: Number(x[k]), background: SEV_COLOR[k] }} title={`${x[k]} ${SEV_LABEL[k].toLowerCase()}`} />
                ))}
              </div>
              <span className="n num">{total(x)}</span>
            </div>
          ))}
          {rows.length > top.length && <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>+{rows.length - top.length} more components</div>}
        </>
      )}
    </Card>
  );
}

function verdict(r: CveRow, notes?: string) {
  const why = notes ? ` (${notes})` : "";
  if (r.status === "fixed") return <>No action: the SBOM marks this CVE fixed{why}.</>;
  if (r.status === "ignored") return <>No action: the SBOM marks this CVE as not affecting the build{why}.</>;
  const shipped = r.carriers.filter((c) => c.shipped === "yes");
  const missing = r.carriers.filter((c) => c.shipped !== "yes");
  const names = (cs: typeof r.carriers) => cs.map((c) => c.name).join(", ");
  if (shipped.length && missing.length) {
    return <>Still relevant. {missing.length === 1 ? "One carrier is" : `${missing.length} carriers are`} not in the image, but <b>{names(shipped)}</b> ships. A CVE only stops mattering when every component that carries it is absent.</>;
  }
  if (shipped.length) return <>Relevant: <b>{names(shipped)}</b> ships in the image.</>;
  if (r.shipped === "build") return <>Not in the image: <b>{names(r.carriers)}</b> is only used at build time. A candidate for VEX <code>not_affected</code> · <code>component_not_present</code>.</>;
  if (r.shipped === "no") return <>Not in the image: none of the files of <b>{names(r.carriers)}</b> are installed. A candidate for VEX <code>not_affected</code> · <code>component_not_present</code>.</>;
  return <>The SBOM doesn't show whether <b>{names(r.carriers)}</b> ships (it declares no files).</>;
}

/** A fix version, linked to its commit when the record gives one. */
function FixLink({ version, commit }: { version: string; commit?: string }) {
  if (!commit) return <code>{version}</code>;
  return <a href={`https://git.kernel.org/stable/c/${commit}`} target="_blank" rel="noreferrer noopener" onClick={(e) => e.stopPropagation()}><code>{version}</code></a>;
}

function FixCell({ c }: { c?: CveCarrier }) {
  if (!c?.fixed_in) return <span className="muted">–</span>;
  return <><FixLink version={c.fixed_in} commit={c.fix_commit} />{c.backport && <sup className="cve-b" title={BACKPORT_NOTE}>B</sup>}</>;
}

/** Kernel CVEs split the fix into the backport for this series and the mainline fix; a userland
 *  CVE has one fix version per carrier, named when there are several. */
function FixRows({ r }: { r: CveRow }) {
  const c = r.carriers.find((x) => x.kernel);
  if (c) {
    return <>
      <span>Backport</span><span>{c.backport ? <FixLink version={c.fixed_in!} commit={c.fix_commit} /> : <span className="muted">none for this series</span>}</span>
      <span>Mainline</span><span>{c.mainline ? <FixLink version={c.mainline} commit={c.mainline_commit} /> : <span className="muted">not in the CVE record</span>}</span>
      {c.stable && <><span>Earliest stable</span><span><FixLink version={c.stable} commit={c.stable_commit} /></span></>}
    </>;
  }
  const fixes = r.carriers.filter((x) => x.fixed_in);
  return <>
    <span>Fixed in</span><span>{!fixes.length ? <span className="muted">not in the CVE record</span>
      : <code>{r.carriers.length === 1 ? fixes[0].fixed_in : fixes.map((x) => `${x.name} ${x.fixed_in}`).join(", ")}</code>}</span>
  </>;
}

function CveSheet({ r, sources, onClose }: { r: CveRow; sources: CveSection["sources"]; onClose: () => void }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  const notes = r.carriers.find((c) => c.status === r.status && c.notes)?.notes;
  return (
    <div className="overlay" onClick={onClose}>
      <aside className="sheet cve-sheet" onClick={(e) => e.stopPropagation()} role="dialog" aria-label={r.id}>
        <button className="icon-btn x" onClick={onClose} aria-label="Close"><X size={15} /></button>
        <h3><code className={nameOnly(r) ? "cve-name-only" : undefined} style={{ fontSize: 15 }}>{r.id}</code></h3>
        {nameOnly(r) && <p className="cve-foot">{NAME_ONLY_NOTE}</p>}
        {r.links && r.links.length > 0 && (
          <div className="adv-pills">
            {r.links.map((l) => (
              <a key={l.kind} href={l.url} target="_blank" rel="noreferrer noopener" title={l.url}>
                {LINK[l.kind]}<ExternalLink size={11} />
              </a>
            ))}
          </div>
        )}

        {r.summary && (
          <>
            <h4>Summary</h4>
            <p className="sum">{r.summary}</p>
          </>
        )}

        <h4>Details</h4>
        <div className="kv">
          <span>Status</span><span><StatusLabel s={r.status} />{notes && <span className="muted"> · {notes}</span>}
            <span className="muted"> · {r.carriers.find((c) => c.status === r.status)?.source === "version-match"
              ? "match from NVD / kernel CNA" : "from the SBOM"}</span></span>
          <FixRows r={r} />
          <span>CVSS</span><span>{r.cvss?.vector ? <span className="vs">{r.cvss.vector}</span> : <span className="muted">not scored</span>}</span>
          <span>KEV</span><span>{!sources.kev ? <span className="muted">not checked</span> : r.kev
            ? <><span className="kev-t">KEV</span> added {r.kev.added}{r.kev.ransomware && " · used in ransomware"}</>
            : <span className="muted">not listed</span>}</span>
          <span>EPSS</span><span>{!sources.epss ? <span className="muted">not checked</span> : r.epss
            ? <><span title="Chance of exploitation in the next 30 days">{r.epss.score.toFixed(3)} · {Math.round(r.epss.percentile * 100)}th percentile</span>{" "}
              <a className="muted" href={`https://api.first.org/data/v1/epss?cve=${r.id}`} target="_blank" rel="noreferrer">source</a></>
            : <span className="muted">no score</span>}</span>
          {r.published && <><span>Published</span><span>{r.published.slice(0, 10)}</span></>}
        </div>

        <h4>Carried by</h4>
        {r.carriers.map((c) => (
          <div className="comp" key={c.name}>
            <code>{c.name} <span className="muted">{c.version}</span></code>
            <span className="chip">
              <i className="swatch" style={{ borderRadius: 999, background: c.shipped === "yes" ? "var(--good)" : c.shipped === "build" ? "var(--neutral)" : c.shipped === "no" ? "var(--critical)" : "var(--axis)" }} />
              {c.shipped === "yes" ? "Shipped" : c.shipped === "build" ? "Build time" : c.shipped === "no" ? "Not in image" : "Unknown"}
            </span>
          </div>
        ))}

        <h4>Relevance</h4>
        <div className="verdict">{verdict(r, notes)}</div>
      </aside>
    </div>
  );
}

export default function Cves({ section, params }: { section: CveSection; params: URLSearchParams }) {
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<string>(params.get("status") ?? "unpatched");
  // Set by the Overview's "CVEs not in image" tile; shown as a removable chip, not a standing filter.
  const [offImage, setOffImage] = useState(params.get("shipped") === "no");
  const [vector, setVector] = useState<string>("all");
  const [kevOnly, setKevOnly] = useState(false);
  const [kernelOnly, setKernelOnly] = useState(false);
  const [open, setOpen] = useState<CveRow | null>(null);
  const rows = section.rows;
  const unmapped = section.unmapped ?? [];
  // Without an SBOM every row is a version match, so the mark would say nothing.
  const outsideSbom = (r: CveRow) => !section.sources.inventory && r.carriers.every((c) => c.source === "version-match");

  // An unpatched CVE only counts on the device; the ones off it show under "CVEs not in image".
  const inScope = (r: CveRow) => (offImage ? !onDevice(r) : r.status !== "unpatched" || onDevice(r));
  const byStatus = useMemo(() => rows.filter((r) => (status === "all" ? !offImage || !onDevice(r) : r.status === status && inScope(r))),
    [rows, status, offImage]);
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return byStatus.filter((r) => (vector === "all" || r.vector === vector) && (!kevOnly || r.kev) && (!kernelOnly || r.kernel) &&
      (!needle || r.id.toLowerCase().includes(needle) || r.carriers.some((c) => c.name.includes(needle)) ||
        (r.summary ?? "").toLowerCase().includes(needle)));
  }, [byStatus, vector, kevOnly, kernelOnly, q]);
  const needle = q.trim().toLowerCase();
  const mapRows = status === "all" || status === "unmapped" ? unmapped.filter((c) => !kevOnly && !kernelOnly && vector === "all" && !offImage && c.name.includes(needle)) : [];
  const listed: (CveRow | { name: string; version: string })[] = useMemo(() => [...shown, ...mapRows], [shown, mapRows.length]);
  const page = usePage(listed, listed);

  const scoped = offImage ? rows.filter((r) => !onDevice(r)) : rows;
  const count = (k: CveStatus) => rows.filter((r) => r.status === k && inScope(r)).length;
  const statusOpts = [
    { value: "unpatched", label: "Unpatched", n: count("unpatched") },
    ...(section.sources.inventory ? [] : [
      { value: "ignored", label: "Ignored", n: count("ignored") },
      { value: "fixed", label: "Fixed", n: count("fixed") },
    ]),
    ...(count("unknown") ? [{ value: "unknown", label: "No status", n: count("unknown") }] : []),
    ...(unmapped.length ? [{ value: "unmapped", label: "Needs mapping", n: unmapped.length }] : []),
    { value: "all", label: "All", n: scoped.length + unmapped.length },
  ];
  const vecOpts = [
    { value: "all", label: "All", n: byStatus.length },
    ...["network", "adjacent", "local", "physical", ""].map((v) => ({
      value: v, label: VECTOR[v], n: byStatus.filter((r) => r.vector === v).length,
    })).filter((o) => o.n > 0),
  ];

  return (
    <div className="grid">
      <Attention s={section.summary} rows={rows} sources={section.sources} />
      <ByComponent s={section.summary} />
      <div className="span-12">
        <div className="toolbar">
          <SearchBox value={q} onChange={setQ} placeholder="CVE, package or text" />
          <Dropdown label="Status" value={status} options={statusOpts} onChange={setStatus} />
          <Dropdown label="Vector" value={vector} options={vecOpts} onChange={setVector} />
          <Switch label="Kernel only" on={kernelOnly} onChange={setKernelOnly} title="Only CVEs in the Linux kernel" />
          <Switch label="KEV only" on={kevOnly} onChange={setKevOnly} disabled={!section.sources.kev}
            title={section.sources.kev ? `CISA KEV catalogue ${section.sources.kev.version}` : "KEV not checked (no network)"} />
          {offImage && (
            <button className="fchip on" onClick={() => setOffImage(false)} title="Show CVEs on every package">
              Not in image <X size={13} className="x-mark" />
            </button>
          )}
          <span className="spacer" />
          <span className="muted num">{shown.length.toLocaleString()} CVEs{mapRows.length > 0 && ` · ${mapRows.length.toLocaleString()} need mapping`}</span>
        </div>
        <div className="table-wrap">
          <table className="cve-table">
            <thead>
              <tr><th>CVE</th><th>Component</th><th title="First upstream version with the fix, from the CVE record. It doesn't show whether the fix was backported.">Fixed in</th><th>Status</th><th>CVSS</th><th>Vector</th><th className="c">Shipped</th><th className="c">KEV</th></tr>
            </thead>
            <tbody ref={page.bodyRef}>
              {page.rows.map((r) => !("id" in r) ? (
                <tr key={`map:${r.name}`}>
                  <td><span className="muted">–</span></td>
                  <td><code>{r.name}</code> <span className="muted">{r.version}</span></td>
                  <td><span className="muted">–</span></td>
                  <td title="No NVD product has this name, so it couldn't be checked for CVEs.">Needs mapping</td>
                  {[0, 1].map((i) => <td key={i}><span className="muted">–</span></td>)}
                  {[0, 1].map((i) => <td key={i} className="c"><span className="muted">–</span></td>)}
                </tr>
              ) : (
                <tr key={r.id} className={`clickable ${open?.id === r.id ? "sel" : ""}`} onClick={() => setOpen(r)}>
                  <td><code className={nameOnly(r) ? "cve-name-only" : undefined} title={nameOnly(r) ? NAME_ONLY_NOTE : undefined}>{r.id}</code>{outsideSbom(r) && <span className="cve-star" title={OUTSIDE_NOTE}>*</span>}</td>
                  <td>
                    <code>{r.carriers[0]?.name}</code> <span className="muted">{r.carriers[0]?.version}</span>
                    {r.carriers.length > 1 && <span className="muted"> +{r.carriers.length - 1}</span>}
                  </td>
                  <td><FixCell c={r.carriers[0]} /></td>
                  <td><StatusLabel s={r.status} /></td>
                  <td><Score r={r} /></td>
                  <td>{r.vector ? VECTOR[r.vector] : <span className="muted">–</span>}</td>
                  <td className="c"><ShippedCell r={r} /></td>
                  <td className="c">{r.kev ? <span className="kev-t">KEV</span> : <span className="muted">–</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {shown.length === 0 && <div className="empty">No CVEs match these filters.</div>}
        </div>
        {shown.some(outsideSbom) && <p className="cve-foot">* {OUTSIDE_NOTE}</p>}
        {shown.some(nameOnly) && <p className="cve-foot"><code className="cve-name-only">CVE-XXXX-YYYY</code> in amber: {NAME_ONLY_NOTE}</p>}
        {shown.some((r) => r.carriers[0]?.backport) && <p className="cve-foot">B {BACKPORT_NOTE}</p>}
        {page.pager}
      </div>
      {open && <CveSheet r={open} sources={section.sources} onClose={() => setOpen(null)} />}
    </div>
  );
}
