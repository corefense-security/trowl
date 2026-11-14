import { Check, ChevronDown, ChevronLeft, ChevronRight, Search } from "lucide-react";
import { useEffect, useLayoutEffect, useRef, useState, type PointerEvent, type ReactNode } from "react";

export const STATUS: Record<string, { label: string; color: string; hint: string }> = {
  present: { label: "In image", color: "var(--good)", hint: "All declared files found with matching hashes" },
  modified: { label: "Changed", color: "var(--warning)", hint: "In image, but some files differ from the SBOM hash" },
  partial: { label: "Partial", color: "var(--serious)", hint: "Some declared files are missing" },
  absent: { label: "Not in image", color: "var(--critical)", hint: "None of the declared files are in the image" },
  "build-only": { label: "Build-time only", color: "var(--neutral)", hint: "Recipe produces nothing that ships" },
  "no-files": { label: "No files declared", color: "var(--violet)", hint: "Meta package; presence can't be decided from files" },
  unknown: { label: "Unknown", color: "var(--axis)", hint: "Only file-less packages; presence undecided" },
};

export function StatusChip({ s }: { s: string }) {
  const st = STATUS[s] ?? STATUS.unknown;
  return (
    <span className="chip" title={st.hint}>
      <span className="swatch" style={{ background: st.color, borderRadius: 999 }} />
      {st.label}
    </span>
  );
}

/** The heading every page section starts with: a title, a short note under it, and optional
 *  figures on the right. */
export function PageHead({ title, note, right }: { title: string; note?: ReactNode; right?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1 className="page-h">{title}</h1>
        {note && <div className="page-note">{note}</div>}
      </div>
      {right && <div className="page-head-r">{right}</div>}
    </div>
  );
}

export function Card({ title, hint, right, className = "", children }: {
  title?: string; hint?: ReactNode; right?: ReactNode; className?: string; children: ReactNode;
}) {
  return (
    <section className={`card ${className}`}>
      {title && (
        <div className="card-h">
          <h2>{title}</h2>
          {hint && <span className="hint">{hint}</span>}
          {right && <span className="right">{right}</span>}
        </div>
      )}
      {children}
    </section>
  );
}

export function SearchBox({ value, onChange, placeholder }: {
  value: string; onChange: (v: string) => void; placeholder: string;
}) {
  return (
    <label className="search">
      <Search size={15} />
      <input value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} />
    </label>
  );
}

/** Compact select. A "Label  Value ▾" button with a menu that closes on outside click or Escape. */
export function Dropdown({ label, value, options, onChange }: {
  label: string; value: string; options: { value: string; label: string; n?: number }[]; onChange: (v: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", away); document.removeEventListener("keydown", esc); };
  }, [open]);
  const current = options.find((o) => o.value === value);
  return (
    <div className="dd" ref={ref}>
      <button className="dd-btn" onClick={() => setOpen(!open)} aria-haspopup="listbox" aria-expanded={open}>
        {label} <b>{current?.label ?? value}</b><ChevronDown size={14} className="muted" />
      </button>
      {open && (
        <div className="dd-menu" role="listbox" aria-label={label}>
          {options.map((o) => (
            <button key={o.value} role="option" aria-selected={o.value === value} className={o.value === value ? "on" : ""}
              onClick={() => { onChange(o.value); setOpen(false); }}>
              {o.label}{o.n !== undefined && <span className="num">{o.n.toLocaleString()}</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/** A dropdown of independent on/off choices, where several can be on. The menu stays open
 *  while choosing. `summary` is what the closed button shows. */
export function MultiDropdown({ label, summary, options, onToggle, align = "left" }: {
  label: string; summary: string;
  options: { value: string; label: string; on: boolean; n?: number; color?: string; hint?: string; disabled?: boolean }[];
  onToggle: (v: string) => void; align?: "left" | "right";
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", away); document.removeEventListener("keydown", esc); };
  }, [open]);
  return (
    <div className="dd" ref={ref}>
      <button className="dd-btn" onClick={() => setOpen(!open)} aria-haspopup="listbox" aria-expanded={open}>
        {label} <b>{summary}</b><ChevronDown size={14} className="muted" />
      </button>
      {open && (
        <div className={`dd-menu dd-multi ${align === "right" ? "dd-right" : ""}`} role="listbox" aria-multiselectable aria-label={label}>
          {options.map((o) => (
            <button key={o.value} role="option" aria-selected={o.on} disabled={o.disabled} title={o.hint}
              onClick={() => onToggle(o.value)}>
              <span className="dd-opt">
                <span className={`dd-check ${o.on ? "on" : ""}`}>{o.on && <Check size={11} />}</span>
                {o.color && <i className="swatch" style={{ background: o.color, borderRadius: 999 }} />}
                {o.label}
              </span>
              {o.n !== undefined && <span className="num">{o.n.toLocaleString()}</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

interface Tip { x: number; y: number; title: string; value: string; color: string }

function useTip() {
  const [tip, setTip] = useState<Tip | null>(null);
  const node = tip && (
    <div className="tip" style={{ left: tip.x + 12, top: tip.y + 12 }}>
      <strong>{tip.value}</strong>
      <span className="ink2" style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
        <span style={{ width: 12, height: 2, background: tip.color, display: "inline-block" }} />
        {tip.title}
      </span>
    </div>
  );
  return { setTip, node };
}

export type Slice = { label: string; value: number; color: string };

/** A donut of parts of one whole. The total sits in the centre and the legend beside it.
 *  Hovering a slice or a legend row highlights that part. `children` go under the legend. */
export function Donut({ slices, center, centerLabel, children }: {
  slices: Slice[]; center: string; centerLabel: string; children?: ReactNode;
}) {
  const { setTip, node } = useTip();
  const [hot, setHot] = useState<number | null>(null);
  const size = 150, c = size / 2, ro = 62, ri = 46;
  const gap = 0.025; // gap between arcs in radians
  const sum = slices.reduce((n, x) => n + x.value, 0);
  const live = slices.filter((x) => x.value > 0).length;

  const pt = (rad: number, a: number) => `${(c + rad * Math.cos(a)).toFixed(2)} ${(c + rad * Math.sin(a)).toFixed(2)}`;
  let acc = -Math.PI / 2;
  const arcs = slices.map((s, i) => {
    const span = sum ? (s.value / sum) * 2 * Math.PI : 0;
    const a0 = acc + (live > 1 ? gap / 2 : 0), a1 = acc + span - (live > 1 ? gap / 2 : 0);
    acc += span;
    if (s.value <= 0 || a1 <= a0) return null;
    if (live === 1) {
      // One full ring is two half arcs because an SVG arc can't close on itself
      const d = `M ${pt(ro, -Math.PI / 2)} A ${ro} ${ro} 0 1 1 ${pt(ro, Math.PI / 2)} A ${ro} ${ro} 0 1 1 ${pt(ro, -Math.PI / 2)}
        M ${pt(ri, -Math.PI / 2)} A ${ri} ${ri} 0 1 0 ${pt(ri, Math.PI / 2)} A ${ri} ${ri} 0 1 0 ${pt(ri, -Math.PI / 2)} Z`;
      return { i, d };
    }
    const large = a1 - a0 > Math.PI ? 1 : 0;
    return { i, d: `M ${pt(ro, a0)} A ${ro} ${ro} 0 ${large} 1 ${pt(ro, a1)} L ${pt(ri, a1)} A ${ri} ${ri} 0 ${large} 0 ${pt(ri, a0)} Z` };
  });

  const enter = (e: PointerEvent, i: number) => {
    setHot(i);
    setTip({ x: e.clientX, y: e.clientY, color: slices[i].color, title: slices[i].label,
      value: `${slices[i].value.toLocaleString()} · ${sum ? Math.round((100 * slices[i].value) / sum) : 0}%` });
  };
  const leave = () => { setHot(null); setTip(null); };

  return (
    <div className="dn">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" className="dn-svg"
        aria-label={`${center} ${centerLabel}: ${slices.map((x) => `${x.label} ${x.value}`).join(", ")}`}>
        <circle cx={c} cy={c} r={(ro + ri) / 2} fill="none" stroke="var(--surface-2)" strokeWidth={ro - ri} />
        {arcs.map((a) => a && (
          <path key={a.i} d={a.d} fill={slices[a.i].color} fillRule="evenodd"
            opacity={hot === null || hot === a.i ? 1 : 0.35} style={{ transition: "opacity 0.15s" }}
            onPointerMove={(e) => enter(e, a.i)} onPointerLeave={leave} />
        ))}
        <text x={c} y={c - 5} textAnchor="middle" dominantBaseline="central" className="dn-n">{center}</text>
        <text x={c} y={c + 16} textAnchor="middle" dominantBaseline="central" className="dn-l">{centerLabel}</text>
      </svg>
      <div className="dn-side">
        <ul className="dn-legend">
          {slices.map((s, i) => (
            <li key={s.label} className={hot !== null && hot !== i ? "dim" : ""}
              onPointerEnter={() => setHot(i)} onPointerLeave={() => setHot(null)}>
              <i className="swatch" style={{ background: s.color }} />
              <span>{s.label}</span>
              <b className="num">{s.value.toLocaleString()}</b>
            </li>
          ))}
        </ul>
        {children}
      </div>
      {node}
    </div>
  );
}

/** Coverage of one protection. `parts` splits it into kinds for the tooltip (RELRO full and partial). */
export type CoverageRow = { label: string; ok: number; total: number; about: string; parts?: { label: string; n: number }[] };

/** One bar per protection with the weakest first.
 *  Each is its own rate. Bars fade as coverage drops so weak ones stand out. */
export function CoverageBars({ rows }: { rows: CoverageRow[] }) {
  const pct = (r: CoverageRow) => (r.total ? Math.round((100 * r.ok) / r.total) : 0);
  const sorted = [...rows].sort((a, b) => pct(a) - pct(b) || a.label.localeCompare(b.label));
  return (
    <ul className="cov">
      {sorted.map((r) => {
        const p = pct(r);
        const tip = [r.about, ...(r.parts ?? []).map((x) => `${x.label}: ${x.n}`)].join("\n");
        return (
          <li key={r.label} title={tip}>
            <span className="cov-l">{r.label}</span>
            <span className="cov-track"><i style={{ width: `${p}%`, opacity: 0.25 + 0.75 * (p / 100) ** 3 }} /></span>
            <b className="num">{p}%</b>
            <span className="cov-f num">{r.ok}/{r.total}</span>
          </li>
        );
      })}
    </ul>
  );
}

/** Trowl mark: three stacked layers of an image, the top two cut open down to the third. */
export function Logo({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden>
      <mask id="trowl-cut">
        <rect width="24" height="24" fill="#fff" />
        <path d="M12 4.5 15.6 2H24V0H0v2h8.4Z M9.6 1 12 13.6 14.4 1Z" fill="#000" />
      </mask>
      <g fill="currentColor">
        <path d="M12 15.6 21.5 11v2.2L12 17.8 2.5 13.2V11Z" opacity={0.55} />
        <g mask="url(#trowl-cut)">
          <path d="M12 3.2 21.5 7.8 12 12.4 2.5 7.8Z" />
          <path d="M12 13.6 21.5 9v2.2L12 15.8 2.5 11.2V9Z" />
        </g>
        <path d="M12 18.4 21.5 13.8v2.6L12 21 2.5 16.4v-2.6Z" />
      </g>
    </svg>
  );
}

/** An on/off filter drawn as a sliding switch with its label. */
export function Switch({ label, on, onChange, title, disabled }: {
  label: string; on: boolean; onChange: (v: boolean) => void; title?: string; disabled?: boolean;
}) {
  return (
    <button className={`switch ${on ? "on" : ""}`} role="switch" aria-checked={on} onClick={() => onChange(!on)} title={title} disabled={disabled}>
      <span className="switch-track"><span className="switch-knob" /></span>{label}
    </button>
  );
}

const PAGE_SIZE = 10; // the minimum. A page grows to fill the window.

/** Paging for a table. Returns the current page's rows, the pager to show under it, and a ref
 *  for the table's <tbody>. The page size fills the window below the table's top edge (at least
 *  PAGE_SIZE rows) and follows resizes. The page resets to the first when `reset` changes (a new
 *  filter or search). With `stacked` (tables sharing a page), the size stays at PAGE_SIZE and
 *  the pager always shows. */
export function usePage<T>(rows: T[], reset: unknown = null, stacked = false) {
  const [page, setPage] = useState(0);
  const [size, setSize] = useState(PAGE_SIZE);
  const bodyRef = useRef<HTMLTableSectionElement>(null);
  useEffect(() => setPage(0), [reset]);
  useLayoutEffect(() => {
    const fit = () => {
      const body = bodyRef.current;
      const first = body?.rows[0];
      if (stacked || !body || !first) return;
      // Measure against the scrolling content area, so the result doesn't depend on scroll.
      const scroller = body.closest(".content") as HTMLElement | null;
      const top = body.getBoundingClientRect().top + (scroller?.scrollTop ?? 0);
      const rowH = body.offsetHeight / body.rows.length || first.offsetHeight;
      const room = window.innerHeight - top - 64; // pager and bottom padding
      setSize(Math.max(PAGE_SIZE, Math.floor(room / rowH)));
    };
    fit();
    window.addEventListener("resize", fit);
    return () => window.removeEventListener("resize", fit);
  }, [rows.length > 0, reset]);
  const pages = Math.max(1, Math.ceil(rows.length / size));
  const p = Math.min(page, pages - 1);
  return {
    rows: rows.slice(p * size, (p + 1) * size),
    pager: <Pager page={p} pages={pages} total={rows.length} size={size} onPage={setPage} always={stacked} />,
    bodyRef,
  };
}

function Pager({ page, pages, total, size, onPage, always }: { page: number; pages: number; total: number; size: number; onPage: (p: number) => void; always: boolean }) {
  if (pages <= 1 && !always) return null;
  const from = page * size + 1, to = Math.min(total, (page + 1) * size);
  return (
    <div className="pager">
      <span className="muted num">{from.toLocaleString()}–{to.toLocaleString()} of {total.toLocaleString()}</span>
      <button className="icon-btn" onClick={() => onPage(page - 1)} disabled={page === 0} aria-label="Previous page"><ChevronLeft size={15} /></button>
      <span className="num pager-n">{(page + 1).toLocaleString()} / {pages.toLocaleString()}</span>
      <button className="icon-btn" onClick={() => onPage(page + 1)} disabled={page >= pages - 1} aria-label="Next page"><ChevronRight size={15} /></button>
    </div>
  );
}
