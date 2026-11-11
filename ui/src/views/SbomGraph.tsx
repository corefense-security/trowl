import cytoscape, { type Core, type ElementDefinition, type NodeSingular } from "cytoscape";
import dagre from "cytoscape-dagre";
import fcose from "cytoscape-fcose";
import { ArrowLeft, Crosshair, Image as ImageIcon, Maximize2, Minus, Network, Plus, Table2, X } from "lucide-react";
import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import type { GraphEdge, GraphNode } from "../types";
import { Dropdown, MultiDropdown, SearchBox, STATUS, StatusChip, usePage } from "../ui";

cytoscape.use(dagre);
cytoscape.use(fcose);

type Layout = "layered" | "radial" | "force";
const STATUS_ORDER = ["present", "modified", "partial", "absent", "no-files", "build-only", "unknown"];

function cssVar(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}
function resolveColor(c: string) {
  const m = c.match(/^var\((--[\w-]+)\)$/);
  return m ? cssVar(m[1]) : c;
}
const openCves = (n: GraphNode) => n.cves.filter((c) => c.vex !== "fixed" && c.vex !== "not_affected").length;

/** Re-render when the theme changes (toggle or OS), so canvas colours follow the CSS tokens. */
function useThemeKey() {
  const [key, setKey] = useState(0);
  useEffect(() => {
    const bump = () => setKey((k) => k + 1);
    const mo = new MutationObserver(bump);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    mq.addEventListener("change", bump);
    return () => { mo.disconnect(); mq.removeEventListener("change", bump); };
  }, []);
  return key;
}

const LAYOUTS: Record<Layout, cytoscape.LayoutOptions> = {
  layered: { name: "dagre", rankDir: "LR", nodeSep: 10, rankSep: 110, edgeSep: 6 } as cytoscape.LayoutOptions,
  radial: {
    name: "concentric", minNodeSpacing: 14,
    concentric: (n: NodeSingular) => n.degree(false), levelWidth: () => 2,
  } as cytoscape.LayoutOptions,
  force: { name: "fcose", quality: "proof", nodeRepulsion: 9000, idealEdgeLength: 70, nodeSeparation: 90 } as cytoscape.LayoutOptions,
};

const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const ms = (d: number) => (reducedMotion() ? 0 : d);
const EASE = "ease-in-out-cubic" as const;

/** Ease the camera onto a node's direct neighbourhood, never so close that a lone node fills the screen. */
function frameNode(c: Core, n: cytoscape.CollectionReturnValue | NodeSingular, duration = 650) {
  const bb = n.closedNeighborhood().boundingBox({});
  const w = c.width(), h = c.height(), pad = 140;
  const zoom = Math.max(0.6, Math.min(1.8, Math.min(w / (bb.w + pad * 2), h / (bb.h + pad * 2))));
  const pan = { x: w / 2 - zoom * (bb.x1 + bb.w / 2), y: h / 2 - zoom * (bb.y1 + bb.h / 2) };
  c.stop();
  c.animate({ zoom, pan }, { duration: reducedMotion() ? 0 : duration, easing: EASE });
}

// Node sizes per state. Recipes are pills (width from label) and packages are circles (size from files).
const grow = (k: number) => (e: NodeSingular) => (e.data("role") === "recipe" ? e.data("width") * (1 + (k - 1) / 2) : e.data("size") * k);
const growH = (k: number) => (e: NodeSingular) => (e.data("role") === "recipe" ? 24 * (1 + (k - 1) / 2) : e.data("size") * k);

// Above this many nodes the graph starts at component level, and drawing switches to cheaper
// settings. Cytoscape stays fluid with a few hundred nodes, but thousands freeze the page.
const BIG = 600;
// Beyond this the package view would freeze the browser, so it isn't offered.
const MAX_PACKAGE_VIEW = 1500;

export default function SbomGraph({ graph, params }: { graph: { nodes: GraphNode[]; edges: GraphEdge[] }; params?: URLSearchParams }) {
  // A link can open the page filtered. ?status=present keeps one status, ?role=recipe|package one kind.
  const onlyStatus = params?.get("status") ?? null;
  const onlyRole = params?.get("role") ?? null;
  const box = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const themeKey = useThemeKey();

  const [viewChoice, setView] = useState<"graph" | "table">(params?.get("view") === "table" ? "table" : "graph");
  const [layout, setLayout] = useState<Layout>("layered");
  const [hidden, setHidden] = useState<Set<string>>(() =>
    new Set(onlyStatus ? STATUS_ORDER.filter((s) => s !== onlyStatus) : ["build-only"]));
  const [showRecipes, setShowRecipes] = useState(onlyRole !== "package");
  // Packages are hidden by default on big SBOMs, and their dependencies are lifted to components.
  const [showPackages, setShowPackages] = useState(() => onlyRole === "package" ? true : onlyRole === "recipe" ? false
    : graph.nodes.filter((n) => n.status !== "build-only").length <= BIG);
  const [query, setQuery] = useState("");
  const [suggestOpen, setSuggestOpen] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  // Where the open card was reached from, so it can be stepped back through.
  const [trail, setTrail] = useState<string[]>([]);
  const selRef = useRef<string | null>(null);
  selRef.current = selected;
  /** Open a node's card, remembering the one it was opened from. */
  const select = (id: string | null) => {
    const cur = selRef.current;
    if (id === cur) return;
    setTrail(id && cur ? [...trail, cur] : []);
    selRef.current = id;
    setSelected(id);
  };
  const back = () => {
    if (trail.length === 0) return;
    const prev = trail[trail.length - 1];
    setTrail(trail.slice(0, -1));
    selRef.current = prev;
    setSelected(prev);
  };
  const [hover, setHover] = useState<{ id: string; x: number; y: number } | null>(null);
  const [zoomPct, setZoomPct] = useState(100);

  const byId = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);
  // Only the kinds the Show filter keeps. Otherwise a package-only status (Changed, Partial)
  // would be offered while only components are shown, where ticking it does nothing.
  const inRole = (n: GraphNode) => (n.role === "recipe" ? showRecipes || !showPackages : showPackages);
  const statusCounts = useMemo(() => {
    const m: Record<string, number> = {};
    graph.nodes.filter(inRole).forEach((n) => { m[n.status] = (m[n.status] ?? 0) + 1; });
    return m;
  }, [graph, showPackages, showRecipes]);

  const rel = useMemo(() => {
    const out = new Map<string, GraphEdge[]>(), inc = new Map<string, GraphEdge[]>();
    graph.edges.forEach((e) => {
      (out.get(e.source) ?? out.set(e.source, []).get(e.source)!).push(e);
      (inc.get(e.target) ?? inc.set(e.target, []).get(e.target)!).push(e);
    });
    return { out, inc };
  }, [graph]);

  const visible = useMemo(() => graph.nodes.filter((n) => !hidden.has(n.status) && inRole(n)),
    [graph, hidden, showRecipes, showPackages]);
  const big = visible.length > BIG;
  // Too many nodes to draw without freezing the page, so the paged table is the only view.
  const tooBig = visible.length > MAX_PACKAGE_VIEW;
  const view = tooBig ? "table" : viewChoice;
  // How many nodes turning packages on would draw. The table pages, so it has no such limit.
  const packageViewSize = useMemo(() => graph.nodes.filter((n) => !hidden.has(n.status)).length, [graph, hidden]);
  const packagesWouldNotDraw = view === "graph" && !showPackages && packageViewSize > MAX_PACKAGE_VIEW;

  const elements = useMemo<ElementDefinition[]>(() => {
    const keep = new Set(visible.map((n) => n.id));
    const nodes = visible.map((n) => ({
      data: {
        id: n.id, label: n.name, role: n.role, status: n.status,
        open: openCves(n), cves: n.cves.length,
        size: n.role === "package" ? Math.max(18, Math.min(44, 12 + 4 * Math.sqrt(n.files?.declared ?? 1))) : 22,
        width: Math.max(44, Math.min(140, n.name.length * 6.6 + 16)),
      },
    }));
    // Build dependencies are shown per component in its side panel, not on the main graph.
    let shown = graph.edges.filter((e) => e.kind !== "build");
    if (!showPackages) {
      // Lift package -> package runtime dependencies to the components that build them.
      const owner = new Map<string, string>();
      graph.edges.forEach((e) => { if (e.kind === "generates") owner.set(e.target, e.source); });
      const seen = new Set<string>();
      shown = shown.flatMap((e) => {
        if (e.kind === "generates") return [];
        const source = owner.get(e.source) ?? e.source, target = owner.get(e.target) ?? e.target;
        const key = `${source}|${target}|${e.kind}`;
        if (source === target || seen.has(key)) return [];
        seen.add(key);
        return [{ ...e, source, target }];
      });
    }
    const edges = shown
      .filter((e) => keep.has(e.source) && keep.has(e.target))
      .map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target, kind: e.kind } }));
    return [...nodes, ...edges];
  }, [visible, graph, showPackages]);

  const layoutRef = useRef(layout);
  layoutRef.current = layout;
  const builtWith = useRef<Layout | null>(null);
  const prevSelected = useRef<string | null>(null);
  // The graph's handlers are bound once, so they call through a ref to the current select.
  const selectRef = useRef(select);
  selectRef.current = select;

  useEffect(() => {
    if (view !== "graph" || !box.current) return;
    const ink = cssVar("--ink"), ink2 = cssVar("--ink-2"), surface = cssVar("--surface"), accent = cssVar("--accent");
    const c = cytoscape({
      container: box.current,
      elements,
      minZoom: 0.08,
      maxZoom: 3,
      // On big graphs, draw a cached texture while panning or zooming and skip edges meanwhile.
      textureOnViewport: big, hideEdgesOnViewport: big, pixelRatio: big ? 1 : "auto",
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)", "font-size": 11, "font-family": cssVar("--font"), color: ink2,
            "text-valign": "bottom", "text-margin-y": 5, "min-zoomed-font-size": 7,
            "text-background-color": surface, "text-background-opacity": 0.75, "text-background-padding": "2px",
            "text-background-shape": "roundrectangle",
            width: "data(size)", height: "data(size)", "background-color": resolveColor(STATUS.unknown.color),
            "border-width": 2, "border-color": surface,
            "underlay-color": accent, "underlay-opacity": 0, "underlay-padding": 6, "underlay-shape": "ellipse",
            "transition-property": big ? "none" : "opacity, width, height, border-width, border-color, underlay-opacity, underlay-padding, font-size",
            "transition-duration": big ? 0 : ms(260), "transition-timing-function": "ease-in-out-sine",
          } as cytoscape.Css.Node,
        },
        {
          selector: "node[role = 'recipe']",
          style: {
            shape: "round-rectangle", width: "data(width)", height: 24, "text-valign": "center", "text-margin-y": 0,
            color: "#ffffff", "font-weight": 600, "text-background-opacity": 0, "underlay-shape": "round-rectangle",
          } as cytoscape.Css.Node,
        },
        ...STATUS_ORDER.map((s) => ({ selector: `node[status = '${s}']`, style: { "background-color": resolveColor(STATUS[s].color) } })),
        { selector: "node[role = 'recipe'][status = 'modified'], node[role = 'recipe'][status = 'build-only'], node[role = 'recipe'][status = 'unknown']", style: { color: "#0b0b0b" } },
        { selector: "node[open > 0]", style: { "border-width": 3, "border-color": cssVar("--critical") } },
        {
          selector: "edge",
          style: {
            width: 1.2, "curve-style": big ? "straight" : "bezier", "target-arrow-shape": "triangle", "arrow-scale": 0.7,
            "line-color": cssVar("--axis"), "target-arrow-color": cssVar("--axis"), opacity: 0.9,
            "transition-property": big ? "none" : "opacity, width, line-color, target-arrow-color", "transition-duration": big ? 0 : ms(260),
          } as cytoscape.Css.Edge,
        },
        { selector: "edge[kind = 'generates']", style: { "line-style": "dashed", "line-dash-pattern": [5, 4] } as cytoscape.Css.Edge },
        { selector: "edge[kind = 'build']", style: { "line-style": "dotted", opacity: 0.55 } },
        // on hover the node swells a little and its own edges come forward
        { selector: "node.hover", style: { width: grow(1.2), height: growH(1.2), "underlay-opacity": 0.12, "z-index": 11 } as cytoscape.Css.Node },
        { selector: "edge.hover", style: { width: 2, opacity: 1, "line-color": ink2, "target-arrow-color": ink2 } },
        // focus mode
        { selector: ".dim", style: { opacity: 0.08 } },
        { selector: "node.near", style: { width: grow(1.12), height: growH(1.12), "font-size": 12, color: ink } as cytoscape.Css.Node },
        {
          selector: "edge.up, edge.down",
          style: { width: 2.4, opacity: 1, "z-index": 9, "line-style": "dashed", "line-dash-pattern": [7, 5], "arrow-scale": 0.9 } as cytoscape.Css.Edge,
        },
        { selector: "edge.up", style: { "line-color": cssVar("--upstream"), "target-arrow-color": cssVar("--upstream") } },
        { selector: "edge.down", style: { "line-color": cssVar("--downstream"), "target-arrow-color": cssVar("--downstream") } },
        {
          selector: "node.focus",
          style: {
            width: grow(1.6), height: growH(1.6), "border-width": 4, "border-color": accent, "z-index": 12,
            "font-size": 13, "font-weight": 700, color: ink, "underlay-opacity": 0.2, "underlay-padding": 10,
          } as cytoscape.Css.Node,
        },
        { selector: "node.pulse", style: { "underlay-opacity": 0.38, "underlay-padding": 22 } as cytoscape.Css.Node },
        { selector: "node.hit", style: { "underlay-color": accent, "underlay-opacity": 0.28, "underlay-padding": 9 } as cytoscape.Css.Node },
      ],
      layout: { ...LAYOUTS[layoutRef.current], animate: false } as cytoscape.LayoutOptions,
    });
    builtWith.current = layoutRef.current;
    prevSelected.current = null;
    c.fit(undefined, 90);
    // A graph wide enough to fit fully can start too small to read. 25% is the floor.
    if (c.zoom() < 0.25) c.zoom({ level: 0.25, renderedPosition: { x: c.width() / 2, y: c.height() / 2 } });
    setZoomPct(Math.round(c.zoom() * 100));
    c.on("zoom", () => setZoomPct(Math.round(c.zoom() * 100)));
    c.on("tap", "node", (ev) => selectRef.current(ev.target.id()));
    c.on("tap", (ev) => { if (ev.target === c) selectRef.current(null); });
    c.on("dbltap", "node", (ev) => {
      c.stop();
      c.animate({ center: { eles: ev.target }, zoom: Math.min(c.zoom() * 1.7, 2.6) }, { duration: ms(420), easing: EASE });
    });
    c.on("mouseover", "node", (ev) => {
      const n = ev.target as NodeSingular;
      n.addClass("hover");
      n.connectedEdges().addClass("hover");
      const p = n.renderedPosition();
      setHover({ id: n.id(), x: p.x, y: p.y });
      box.current!.style.cursor = "pointer";
    });
    c.on("mouseout", "node", (ev) => {
      ev.target.removeClass("hover");
      ev.target.connectedEdges().removeClass("hover");
      setHover(null);
      box.current!.style.cursor = "";
    });
    c.on("pan zoom", () => setHover(null));
    cy.current = c;
    return () => { c.destroy(); cy.current = null; };
  }, [elements, view, themeKey, big]);

  // Switching layout moves the existing nodes instead of rebuilding the graph.
  useEffect(() => {
    const c = cy.current;
    if (!c || builtWith.current === layout) return;
    builtWith.current = layout;
    c.stop();
    const focus = prevSelected.current ? c.getElementById(prevSelected.current) : null;
    const run = c.layout({
      ...LAYOUTS[layout], animate: !reducedMotion(), animationDuration: 700, animationEasing: EASE,
      fit: !focus || focus.empty(), padding: 90,
    } as cytoscape.LayoutOptions);
    // with a selection, follow it to its new position instead of fitting the whole graph
    if (focus && !focus.empty()) run.one("layoutstop", () => frameNode(c, focus, 450));
    run.run();
  }, [layout]);

  // Focus mode: ease the camera onto the node and its neighbours, grow it, pulse once, and run
  // a slow dash along what it depends on (blue) and what depends on it (orange).
  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.elements().removeClass("dim up down focus near pulse");
    const was = prevSelected.current;
    prevSelected.current = selected;
    if (!selected) {
      if (was) {
        c.stop();
        c.animate({ fit: { eles: c.elements(), padding: 90 } }, { duration: ms(550), easing: EASE });
      }
      return;
    }
    const n = c.getElementById(selected);
    if (n.empty()) return;
    const up = n.successors(), down = n.predecessors();
    c.elements().addClass("dim");
    n.removeClass("dim").addClass("focus");
    up.removeClass("dim"); down.removeClass("dim");
    n.neighborhood("node").addClass("near");
    up.edges().addClass("up"); down.edges().addClass("down");
    n.flashClass("pulse", ms(320));

    frameNode(c, n);

    if (reducedMotion()) return;
    const flowing = c.edges(".up, .down");
    let offset = 0, raf = 0, last = 0;
    const tick = (t: number) => {
      if (t - last > 33) { // ~30 fps is plenty for a dash drift
        offset -= 1.2;
        flowing.style("line-dash-offset", offset);
        last = t;
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => { cancelAnimationFrame(raf); if (!c.destroyed()) flowing.removeStyle("line-dash-offset"); };
  }, [selected, elements, themeKey]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") select(null); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.nodes().removeClass("hit");
    if (query.length < 2) return;
    c.nodes().filter((n) => String(n.data("label")).toLowerCase().includes(query.toLowerCase())).addClass("hit");
  }, [query, elements, themeKey]);

  const suggestions = query.length >= 1
    ? visible.filter((n) => n.name.toLowerCase().includes(query.toLowerCase())).slice(0, 12) : [];

  const presentStatuses = STATUS_ORDER.filter((s) => statusCounts[s]);
  const shownStatuses = presentStatuses.filter((s) => !hidden.has(s));
  const statusSummary = shownStatuses.length === presentStatuses.length ? "All"
    : shownStatuses.length === 1 ? STATUS[shownStatuses[0]].label
    : shownStatuses.length === 0 ? "None" : `${shownStatuses.length} of ${presentStatuses.length}`;
  const showSummary = showPackages ? (showRecipes ? "Components + packages" : "Packages") : "Components";
  const toggleStatus = (s: string) => {
    const n = new Set(hidden);
    if (n.has(s)) n.delete(s); else n.add(s);
    setHidden(n);
  };
  const zoomBy = (k: number) => {
    const c = cy.current;
    if (!c) return;
    c.stop();
    c.animate({ zoom: { level: Math.max(0.08, Math.min(3, c.zoom() * k)), renderedPosition: { x: c.width() / 2, y: c.height() / 2 } } },
      { duration: ms(220), easing: EASE });
  };
  const exportPng = () => {
    const c = cy.current;
    if (!c) return;
    const a = document.createElement("a");
    a.href = c.png({ full: true, scale: 2, bg: cssVar("--page") });
    a.download = "sbom-graph.png";
    a.click();
  };

  const sel = selected ? byId.get(selected) : null;
  const hov = hover ? byId.get(hover.id) : null;

  return (
    <div className="gw">
      <div className="gw-canvas">
        <div className="gw-panel gw-top">
          <div style={{ position: "relative" }}>
            <SearchBox value={query} placeholder="Find a package or recipe"
              onChange={(v) => { setQuery(v); setSuggestOpen(true); }} />
            {suggestOpen && suggestions.length > 0 && (
              <div className="gw-suggest" onMouseLeave={() => setSuggestOpen(false)}>
                {suggestions.map((n) => (
                  <button key={n.id} onClick={() => { select(n.id); setView("graph"); setSuggestOpen(false); }}>
                    <span className="swatch" style={{ background: STATUS[n.status]?.color, borderRadius: n.role === "recipe" ? 3 : 999 }} />
                    <span>{n.name}</span>
                    <span className="muted" style={{ marginLeft: "auto", fontSize: 12 }}>{n.role}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
          <div className="seg">
            <button className={view === "graph" ? "on" : ""} onClick={() => setView("graph")} disabled={tooBig}
              title={tooBig ? `${visible.length.toLocaleString()} nodes is too many to draw; narrow the filters to see the graph` : undefined}>
              <Network size={14} /> Graph</button>
            <button className={view === "table" ? "on" : ""} onClick={() => setView("table")}><Table2 size={14} /> Table</button>
          </div>
          {view === "graph" && (
            <Dropdown label="Layout" value={layout} options={[
              { value: "layered", label: "Layered" },
              { value: "radial", label: "Radial" },
              { value: "force", label: "Force" },
            ]} onChange={(v) => setLayout(v as Layout)} />
          )}
          <span className="spacer" />
          <MultiDropdown label="Status" align="right" summary={statusSummary} onToggle={toggleStatus}
            options={presentStatuses.map((s) => ({ value: s, label: STATUS[s].label, on: !hidden.has(s), n: statusCounts[s],
              color: STATUS[s].color, hint: STATUS[s].hint }))} />
          <MultiDropdown label="Show" align="right" summary={showSummary}
            onToggle={(v) => v === "packages" ? setShowPackages(!showPackages) : setShowRecipes(!showRecipes)}
            options={[
              { value: "packages", label: "Packages", on: showPackages,
                disabled: packagesWouldNotDraw,
                hint: showPackages ? "Off: components only, with package dependencies lifted to them"
                  : packagesWouldNotDraw ? `${packageViewSize.toLocaleString()} nodes is too many to draw; switch to the Table view to include packages`
                  : "Show the binary packages each component builds" },
              { value: "recipes", label: "Components", on: showRecipes || !showPackages, disabled: !showPackages,
                hint: showPackages ? "Show the build components (recipes) next to their packages" : "Always shown when packages are off" },
            ]} />
        </div>

        {view === "graph" ? (
          <>
            <div ref={box} className="cy" />
            {hov && hover && (
              <div className="gw-panel gw-hover" style={{ left: hover.x + 18, top: hover.y + 18 }}>
                <strong>{hov.name}</strong>
                <span className="muted">{hov.role} · {hov.version || "no version"}</span>
                <StatusChip s={hov.status} />
                {hov.files && <span className="ink2">{hov.files.present}/{hov.files.declared} files present</span>}
                {hov.cves.length > 0 && <span className="ink2">{hov.cves.length} CVEs · <b className={openCves(hov) ? "no" : ""}>{openCves(hov)} open</b></span>}
              </div>
            )}
            <div className="gw-panel gw-legend">
              <div className="row"><span className="shape-r" /> Recipe (source)</div>
              <div className="row"><span className="shape-c" /> Binary package, sized by file count</div>
              <div className="row"><span className="ring" /> Has open CVEs</div>
              <div className="row"><span className="line" style={{ borderColor: "var(--upstream)" }} /> Depends on (selection)</div>
              <div className="row"><span className="line" style={{ borderColor: "var(--downstream)" }} /> Required by (selection)</div>
              <div className="row"><span className="line" style={{ borderColor: "var(--axis)", borderTopStyle: "dashed" }} /> Recipe builds package</div>
            </div>
            <div className="gw-panel gw-stats num">
              {visible.length} nodes · {elements.length - visible.length} edges · {zoomPct}%
            </div>
            <div className="gw-panel gw-zoom">
              <button onClick={() => zoomBy(1.3)} aria-label="Zoom in"><Plus size={16} /></button>
              <button onClick={() => zoomBy(1 / 1.3)} aria-label="Zoom out"><Minus size={16} /></button>
              <button onClick={() => { cy.current?.stop(); cy.current?.animate({ fit: { eles: cy.current.elements(), padding: 90 } }, { duration: ms(450), easing: EASE }); }} aria-label="Fit"><Maximize2 size={15} /></button>
              {sel && <button onClick={() => cy.current?.animate({ center: { eles: cy.current.getElementById(sel.id) } }, { duration: ms(350), easing: EASE })} aria-label="Center selection"><Crosshair size={15} /></button>}
              <button onClick={exportPng} aria-label="Export PNG"><ImageIcon size={15} /></button>
            </div>
          </>
        ) : (
          <NodeTable nodes={visible} selected={selected} onSelect={select} />
        )}
      </div>
      {sel && <NodeDrawer n={sel} rel={rel} byId={byId} onSelect={select} onClose={() => select(null)}
        backTo={trail.length ? byId.get(trail[trail.length - 1]) ?? null : null} onBack={back} />}
    </div>
  );
}

function NodeTable({ nodes, selected, onSelect }: { nodes: GraphNode[]; selected: string | null; onSelect: (id: string) => void }) {
  const rows = useMemo(() => [...nodes].sort((a, b) => openCves(b) - openCves(a) || b.cves.length - a.cves.length || a.name.localeCompare(b.name)), [nodes]);
  const page = usePage(rows, nodes);
  // Components have no file list, so the column is dropped when nothing shown can fill it.
  const anyFiles = useMemo(() => nodes.some((n) => n.files), [nodes]);
  return (
    <div className="gw-panel gw-table">
      <table>
        <thead><tr><th>Name</th><th>Kind</th><th>Version</th><th>Status</th>{anyFiles && <th className="c">Files</th>}<th className="c">CVEs</th><th className="c">Open</th></tr></thead>
        <tbody ref={page.bodyRef}>
          {page.rows.map((n) => (
            <tr key={n.id} className={`clickable ${selected === n.id ? "sel" : ""}`} onClick={() => onSelect(n.id)}>
              <td><b>{n.name}</b></td>
              <td className="ink2">{n.role}</td>
              <td className="ink2">{n.version}</td>
              <td><StatusChip s={n.status} /></td>
              {anyFiles && <td className="c num">{n.files ? `${n.files.present}/${n.files.declared}` : "–"}</td>}
              <td className="c num">{n.cves.length || "–"}</td>
              <td className="c num">{openCves(n) ? <b className="no">{openCves(n)}</b> : "–"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {page.pager}
    </div>
  );
}

function NodeDrawer({ n, rel, byId, onSelect, onClose, backTo, onBack }: {
  n: GraphNode;
  rel: { out: Map<string, GraphEdge[]>; inc: Map<string, GraphEdge[]> };
  byId: Map<string, GraphNode>;
  onSelect: (id: string) => void;
  onClose: () => void;
  backTo: GraphNode | null;
  onBack: () => void;
}) {
  const out = rel.out.get(n.id) ?? [], inc = rel.inc.get(n.id) ?? [];
  const groups: [string, string[]][] = [
    ["Built by recipe", inc.filter((e) => e.kind === "generates").map((e) => e.source)],
    ["Produces packages", out.filter((e) => e.kind === "generates").map((e) => e.target)],
    ["Depends on (runtime)", out.filter((e) => e.kind === "runtime").map((e) => e.target)],
    ["Required by (runtime)", inc.filter((e) => e.kind === "runtime").map((e) => e.source)],
    ["Needed to build", inc.filter((e) => e.kind === "build").map((e) => e.source)],
  ];
  const buildDeps = out.filter((e) => e.kind === "build").map((e) => e.target);
  const open = openCves(n);
  return (
    <aside className="gw-drawer">
      <button className="icon-btn x" onClick={onClose} aria-label="Close"><X size={15} /></button>
      {backTo && (
        <button className="gw-back" onClick={onBack} title={`Back to ${backTo.name}`} aria-label={`Back to ${backTo.name}`}>
          <ArrowLeft size={14} />{backTo.name}
        </button>
      )}
      <div className="muted" style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: 0.5 }}>{n.role === "recipe" ? "Recipe" : "Binary package"}</div>
      <h3>{n.name}</h3>
      <div className="ink2" style={{ marginBottom: 10 }}>{n.version || "no version"}</div>
      <StatusChip s={n.status} />
      <p className="muted" style={{ fontSize: 12.5 }}>{STATUS[n.status]?.hint}</p>

      <div className="stat-row">
        <div><b className="num">{n.files ? `${n.files.present}/${n.files.declared}` : "–"}</b><span>files present</span></div>
        <div><b className="num">{n.cves.length}</b><span>CVEs in SBOM</span></div>
        <div><b className={`num ${open ? "no" : ""}`}>{open}</b><span>not fixed / n.a.</span></div>
      </div>

      {buildDeps.length > 0 && <BuildDeps n={n} ids={buildDeps} byId={byId} onSelect={onSelect} />}

      {groups.filter(([, ids]) => ids.length).map(([label, ids]) => (
        <div key={label}>
          <h4>{label} <span className="num">({ids.length})</span></h4>
          <div className="rel">
            {ids.slice(0, 40).map((id) => {
              const m = byId.get(id);
              return m ? (
                <button key={id} onClick={() => onSelect(id)}>
                  <span className="swatch" style={{ background: STATUS[m.status]?.color, borderRadius: m.role === "recipe" ? 3 : 999 }} />{m.name}
                </button>
              ) : null;
            })}
            {ids.length > 40 && <span className="muted">+{ids.length - 40} more</span>}
          </div>
        </div>
      ))}

      {n.files && (n.files.missing_paths.length > 0 || n.files.modified_paths.length > 0) && (
        <>
          <h4>File differences</h4>
          {n.files.missing_paths.map((p) => <div key={p} className="file-row"><span className="no">missing</span><code>{p}</code></div>)}
          {n.files.modified_paths.map((p) => <div key={p} className="file-row"><span className="part">changed</span><code>{p}</code></div>)}
        </>
      )}

      {n.cves.length > 0 && (
        <>
          <h4>CVEs <span className="muted" style={{ textTransform: "none", letterSpacing: 0 }}>· colour = SBOM VEX status</span></h4>
          <div className="cves">
            {[...n.cves].sort((a, b) => a.id.localeCompare(b.id)).map((c) => (
              <span key={c.id} className={`cve vex-${c.vex || "none"}`} title={c.vex || "no VEX in SBOM"}>{c.id}</span>
            ))}
          </div>
        </>
      )}

      {(n.purl || n.cpes.length > 0) && (
        <>
          <h4>Identifiers</h4>
          <dl className="kv">
            {n.purl && (<><dt>purl</dt><dd><code>{n.purl}</code></dd></>)}
            {n.cpes.map((c) => (<Fragment key={c}><dt>cpe</dt><dd><code>{c}</code></dd></Fragment>))}
          </dl>
        </>
      )}
    </aside>
  );
}

/** A component's build dependencies as a small fan, with the component on the left and one curve
 *  to each thing it needs at build time. Click a dependency to open it. */
function BuildDeps({ n, ids, byId, onSelect }: {
  n: GraphNode; ids: string[]; byId: Map<string, GraphNode>; onSelect: (id: string) => void;
}) {
  const [all, setAll] = useState(false);
  const deps = ids.map((id) => byId.get(id)).filter((m): m is GraphNode => !!m)
    .sort((a, b) => a.name.localeCompare(b.name));
  const LIMIT = 12, ROW = 26, W = 344, LEFT = 118, RIGHT_X = 158;
  const shown = all ? deps : deps.slice(0, LIMIT);
  const h = Math.max(ROW, shown.length * ROW);
  const cy = h / 2;
  return (
    <div>
      <h4>Build dependencies <span className="num">({deps.length})</span></h4>
      <div className="bdeps" style={{ height: h }}>
        <svg width={W} height={h} aria-hidden>
          {shown.map((m, i) => {
            const y = i * ROW + ROW / 2;
            return <path key={m.id} d={`M ${LEFT} ${cy} C ${LEFT + 26} ${cy}, ${RIGHT_X - 26} ${y}, ${RIGHT_X} ${y}`} />;
          })}
        </svg>
        <div className="bdeps-self" style={{ top: cy - 13, width: LEFT }} title={n.name}>
          <span className="swatch" style={{ background: STATUS[n.status]?.color, borderRadius: 3 }} />{n.name}
        </div>
        {shown.map((m, i) => (
          <button key={m.id} className="bdeps-dep" style={{ top: i * ROW + 2, left: RIGHT_X }} onClick={() => onSelect(m.id)}
            title={`${m.name} · ${STATUS[m.status]?.label ?? m.status}`}>
            <span className="swatch" style={{ background: STATUS[m.status]?.color, borderRadius: m.role === "recipe" ? 3 : 999 }} />{m.name}
          </button>
        ))}
      </div>
      {deps.length > LIMIT && (
        <button className="share-link" onClick={() => setAll(!all)}>
          {all ? "Show fewer" : `Show all ${deps.length}`}
        </button>
      )}
    </div>
  );
}
