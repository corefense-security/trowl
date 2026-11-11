import { Check, CircleHelp, Minus, X } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import type { Binary } from "../types";
import { Dropdown, PageHead, SearchBox, usePage, Switch } from "../ui";

type SortKey = "kind";

const HELP: Record<string, string> = {
  PIE: "Position-independent executable: loaded at a random address, so ASLR applies. Libraries are always position-independent (–).",
  NX: "Non-executable stack: code injected onto the stack cannot run.",
  RELRO: "Relocation read-only. Full: the GOT is read-only after startup (-z relro -z now). Partial: the lazily bound part stays writable.",
  Canary: "Stack protector: a guard value catches stack buffer overflows before the function returns (-fstack-protector-strong).",
  Fortify: "_FORTIFY_SOURCE: libc calls whose buffer size is known go through bounds-checked *_chk versions. Shows checked / fortifiable functions called; click a value for the list.",
  IBT: "Intel CET indirect branch tracking (CFI): indirect jumps may only land on marked entry points. Shows how the binary was built; the kernel must also enforce it.",
  SHSTK: "Intel CET shadow stack: return addresses are checked against a protected copy. Shows how the binary was built; the kernel must also enforce it.",
  BTI: "Arm branch target identification (CFI): indirect branches may only land on marked entry points.",
  PAC: "Arm pointer authentication: return addresses are signed and checked.",
  "Search path": "RPATH / RUNPATH embedded in the binary. Relative or user-writable entries let a local user inject libraries.",
};

// `soft` is for informational properties (CET/BTI). Their absence isn't a finding, so no red.
function Mark({ v, soft = false }: { v: boolean | null | undefined; soft?: boolean }) {
  if (v === null || v === undefined) return <Minus size={15} className="muted" aria-label="not applicable" />;
  return v ? <Check size={16} className="ink2" aria-label="yes" /> : <X size={16} className={soft ? "muted" : "no"} aria-label="no" />;
}

/** The canary and FORTIFY checks both match symbol names. A stripped static binary has none,
 *  which would look like "no protection" unless shown separately. */
function CanaryCell({ b }: { b: Binary }) {
  if (b.no_symbols) {
    return <span className="muted" title="Statically linked and stripped: no symbol names left to check for __stack_chk_* references.">n/a (stripped)</span>;
  }
  return <Mark v={b.canary} />;
}

/** A list of function names. Shows the first `max`, then "+N more". */
function FnList({ names, cls, max = 5 }: { names: string[]; cls: string; max?: number }) {
  const [all, setAll] = useState(false);
  const shown = all ? names : names.slice(0, max);
  return (
    <div className="cves">
      {shown.map((n) => <code key={n} className={`fn ${cls}`}>{n}</code>)}
      {names.length > max && (
        <button className="fn-more" onClick={() => setAll(!all)}>
          {all ? "show fewer" : `+${names.length - max} more`}
        </button>
      )}
    </div>
  );
}

/** Column header with a help icon whose tooltip explains the column. */
function HeadTip({ label, children }: { label: string; children?: ReactNode }) {
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);
  const text = HELP[label];
  return (
    <span className="th-tip">
      {children ?? label}
      {text && (
        <span
          className="th-i" tabIndex={0} aria-label={text}
          onPointerEnter={(e) => { const r = e.currentTarget.getBoundingClientRect(); setPos({ x: r.left, y: r.bottom }); }}
          onPointerLeave={() => setPos(null)}
          onFocus={(e) => { const r = e.currentTarget.getBoundingClientRect(); setPos({ x: r.left, y: r.bottom }); }}
          onBlur={() => setPos(null)}
        >
          <CircleHelp size={12} strokeWidth={2.25} />
        </span>
      )}
      {pos && text && <span className="tip head" style={{ left: Math.min(pos.x - 8, window.innerWidth - 300), top: pos.y + 8 }}><b>{label}</b>{text}</span>}
    </span>
  );
}

function FortifyCell({ b, onOpen }: { b: Binary; onOpen: () => void }) {
  const f = b.fortify;
  const total = f ? f.fortified + f.unfortified : 0;
  if (b.no_symbols) {
    return <span className="muted" title="Statically linked and stripped: no symbol names left to check for *_chk variants.">n/a (stripped)</span>;
  }
  if (!f || total === 0) return <span className="muted" title="Calls none of the libc functions _FORTIFY_SOURCE can guard.">n/a</span>;
  const word = f.fortified === 0 ? "none" : f.unfortified === 0 ? "full" : "partial";
  return (
    <button className={`fort fort-${word}`} onClick={onOpen} title="Show functions">
      {word} <span className="num">{f.fortified}/{total}</span>
    </button>
  );
}

// Colour, label and count for each band of the bar. These are the three groups listed below it.
const BANDS: [string, string, (f: NonNullable<Binary["fortify"]>) => number][] = [
  ["fn-ok", "Checked", (f) => (f.checked ?? []).length],
  ["fn-mixed", "Partly checked", (f) => (f.mixed ?? []).length],
  ["fn-no", "Unchecked", (f) => (f.unchecked ?? []).length],
];

function FortifySheet({ b, onClose }: { b: Binary; onClose: () => void }) {
  const f = b.fortify!;
  const checked = f.checked ?? [], mixed = f.mixed ?? [], unchecked = f.unchecked ?? [];
  const legacy = !f.checked; // report from an older trowl without per-function lists
  const group = (title: string, hint: string, names: string[], cls: string) => names.length > 0 && (
    <>
      <h4>{title} <span className="num">({names.length})</span></h4>
      <p className="muted" style={{ margin: "0 0 8px", fontSize: 12.5 }}>{hint}</p>
      <FnList names={names} cls={cls} />
    </>
  );
  return (
    <div className="overlay" onClick={onClose}>
      <aside className="sheet" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="Fortify details">
        <button className="icon-btn x" onClick={onClose} aria-label="Close"><X size={15} /></button>
        <div className="muted" style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: 0.5 }}>Fortify</div>
        <h3><code style={{ fontSize: 15 }}>{b.path}</code></h3>
        <p className="ink2" style={{ fontSize: 13 }}>
          With <code>-D_FORTIFY_SOURCE</code>, the compiler routes a libc call through a bounds-checked <code>__name_chk</code>{" "}
          version whenever it knows the destination buffer's size. Calls where the size isn't known at compile time stay unchecked.
          trowl reads this from the symbols the binary imports, so it counts functions, not individual call sites.
        </p>
        <div className="fort-sum">
          <b className="num">{checked.length + mixed.length + unchecked.length}</b>
          <span>fortifiable libc function{checked.length + mixed.length + unchecked.length === 1 ? "" : "s"} called</span>
        </div>
        <div className="fort-bar" role="img"
          aria-label={BANDS.map(([, label, n]) => `${n(f)} ${label.toLowerCase()}`).join(", ")}>
          {BANDS.map(([cls, , n]) => n(f) > 0 && <i key={cls} className={cls} style={{ flex: n(f) }} />)}
        </div>
        <div className="fort-legend">
          {BANDS.map(([cls, label, n]) => n(f) > 0 && (
            <span key={cls}><i className={`swatch ${cls}`} />{label} <b className="num">{n(f)}</b></span>
          ))}
        </div>
        {legacy ? (
          <p className="muted">This report predates per-function detail; rescan to see the function list.</p>
        ) : (
          <>
            {group("Checked", "Every call uses the __name_chk version.", checked, "fn-ok")}
            {group("Partly checked", "Both versions are linked: some call sites are checked, others had no known buffer size.", mixed, "fn-mixed")}
            {group("Unchecked", "Only the plain version is called. If no function is checked at all, the binary was likely built without _FORTIFY_SOURCE.", unchecked, "fn-no")}
          </>
        )}
      </aside>
    </div>
  );
}

const isSetuid = (b: Binary) => ((b.mode ?? 0) & 0o4000) !== 0;

export default function Binaries({ binaries, params }: { binaries: Binary[]; params: URLSearchParams }) {
  const [q, setQ] = useState("");
  // The Overview's setuid tile opens this page with both set.
  const [kind, setKind] = useState(params.get("setuid") ? "executable" : "");
  const [setuid, setSetuid] = useState(!!params.get("setuid"));
  const [rootOwned, setRootOwned] = useState(!!params.get("setuid"));
  const [sort, setSort] = useState<{ k: SortKey; asc: boolean } | null>(null);
  const [fortify, setFortify] = useState<Binary | null>(null);

  const judged = useMemo(() => binaries.filter((b) => b.kind === "executable" || b.kind === "library"), [binaries]);
  const cfKeys = useMemo(() => Array.from(new Set(judged.flatMap((b) => Object.keys(b.cf_protection ?? {})))), [judged]);

  const shown = judged
    .filter((b) => (!q || b.path.toLowerCase().includes(q.toLowerCase())) && (!kind || b.kind === kind) &&
      (kind === "library" || (!setuid && !rootOwned) ||
        (b.kind === "executable" && (!setuid || isSetuid(b)) && (!rootOwned || b.uid === 0))))
    .sort((a, b) => {
      const d = a.kind.localeCompare(b.kind) || a.path.localeCompare(b.path);
      return !sort ? a.path.localeCompare(b.path) : sort.asc ? d : -d;
    });

  const page = usePage(shown, `${q}|${kind}|${setuid}|${rootOwned}|${sort?.k}|${sort?.asc}`);

  const hasPerms = judged.some((b) => b.mode !== undefined);
  const typeOpts = [
    { value: "", label: "All", n: judged.length },
    { value: "executable", label: "Executables", n: judged.filter((b) => b.kind === "executable").length },
    { value: "library", label: "Libraries", n: judged.filter((b) => b.kind === "library").length },
  ];

  const th = (k: SortKey, label: string) => (
    <th className="sortable" onClick={() => setSort({ k, asc: sort?.k === k ? !sort.asc : true })}>
      {label}{sort?.k === k ? (sort.asc ? " ↑" : " ↓") : ""}
    </th>
  );

  return (
    <>
      <section className="card page-card">
        <PageHead title="Binary Hardening"
          note={`Compile-time hardening, UID 0 and setuid root binaries`} />
      </section>
      <div className="toolbar">
        <SearchBox value={q} onChange={setQ} placeholder="Filter by path" />
        <Dropdown label="Type" value={kind} options={typeOpts} onChange={setKind} />
        {kind !== "library" && hasPerms && <>
          <Switch label="uid 0" on={rootOwned} onChange={setRootOwned} title="Only executables owned by root" />
          <Switch label="setuid" on={setuid} onChange={setSetuid} title="Only executables that run as their owner, whoever starts them" />
        </>}
        <span className="spacer" />
        <span className="muted">{shown.length} of {judged.length}</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Path</th>
              {th("kind", "Type")}
              {["PIE", "NX", "RELRO", "Canary", "Fortify", ...cfKeys.map((k) => k.toUpperCase())].map((h) => (
                <th key={h} className="c"><HeadTip label={h} /></th>
              ))}
              <th><HeadTip label="Search path" /></th>
            </tr>
          </thead>
          <tbody ref={page.bodyRef}>
            {page.rows.map((b) => (
              <tr key={b.path}>
                <td className="ellipsis" style={{ maxWidth: 380 }}><code>{b.path}</code></td>
                <td className="ink2">{b.kind}{b.static ? " · static" : ""}</td>
                <td className="c"><Mark v={b.pie} /></td>
                <td className="c"><Mark v={b.nx} /></td>
                <td className="c"><span className={b.relro === "full" ? "ink2" : b.relro === "partial" ? "relro-partial" : "no"}>{b.relro}</span></td>
                <td className="c"><CanaryCell b={b} /></td>
                <td className="c"><FortifyCell b={b} onOpen={() => setFortify(b)} /></td>
                {cfKeys.map((k) => <td key={k} className="c"><Mark v={b.cf_protection?.[k]} soft /></td>)}
                <td><code className="muted">{[...(b.rpath ?? []), ...(b.runpath ?? [])].join(":")}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {page.pager}
      {fortify && <FortifySheet b={fortify} onClose={() => setFortify(null)} />}
    </>
  );
}
