export type Severity = "info" | "low" | "medium" | "high" | "critical";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Finding {
  check: string;
  severity: Severity;
  path: string;
  title: string;
  detail: string;
  evidence: Record<string, unknown>;
}

export interface Fortify {
  fortified: number;
  unfortified: number;
  checked?: string[];
  mixed?: string[];
  unchecked?: string[];
}

export interface Binary {
  path: string;
  kind: string;
  arch: string;
  static: boolean;
  nx?: boolean;
  pie?: boolean | null;
  relro?: "none" | "partial" | "full";
  canary?: boolean;
  fortify?: Fortify;
  rpath?: string[];
  runpath?: string[];
  stripped?: boolean;
  cf_protection?: Record<string, boolean> | null;
  /** No symbol names at all to check canary/FORTIFY against (a stripped static binary; a
   *  stripped dynamic one keeps .dynsym, so this is almost always a static+stripped case). */
  no_symbols?: boolean;
  /** From the image itself; absent if it couldn't be read. */
  mode?: number;
  uid?: number;
  gid?: number;
}

export interface GraphNode {
  id: string;
  name: string;
  version: string;
  role: "recipe" | "package";
  purl: string;
  cpes: string[];
  status: string;
  files?: {
    declared: number;
    present: number;
    modified: number;
    missing: number;
    modified_paths: string[];
    missing_paths: string[];
  } | null;
  cves: { id: string; vex: string }[];
}

export interface GraphEdge {
  source: string;
  target: string;
  kind: "generates" | "runtime" | "build";
}

export type CveStatus = "unpatched" | "ignored" | "fixed" | "unknown";
export type Shipped = "yes" | "build" | "no" | "unknown";

export interface CveCarrier {
  name: string;
  version: string;
  shipped: Shipped;
  status: CveStatus;
  notes: string;
  kernel: boolean;
  /** Where the status comes from: the SBOM's own VEX, or trowl's version match. */
  source?: "sbom" | "version-match";
  /** First upstream version with the fix, from the CVE record; "" if it gives none. */
  fixed_in?: string;
  /** Kernel only: the commit for fixed_in, whether fixed_in is the backport to this kernel's
   *  stable series, and the mainline fix. */
  fix_commit?: string;
  backport?: boolean;
  mainline?: string;
  mainline_commit?: string;
  /** Earliest stable release with the fix, when it isn't a backport to this series. */
  stable?: string;
  stable_commit?: string;
}

export interface CveRow {
  id: string;
  status: CveStatus;
  shipped: Shipped;
  cvss: { score: number; vector: string; severity: string; version: string } | null;
  severity: "critical" | "high" | "medium" | "low" | "none";
  vector: "" | "network" | "adjacent" | "local" | "physical";
  summary: string;
  published: string;
  kernel: boolean;
  carriers: CveCarrier[];
  kev: { added: string; name: string; ransomware: boolean; due: string } | null;
  epss: { score: number; percentile: number } | null;
  links: { kind: "nvd" | "osv" | "cve" | "kernel"; url: string }[] | null;
}

export interface CveSection {
  summary: {
    status: Partial<Record<CveStatus, number>>;
    unpatched_shipped: number;
    unpatched_not_shipped: number;
    high: number;
    kev: number;
    severity: Record<string, number>;
    by_component: ({ name: string } & Record<string, number | string>)[];
  };
  sources: {
    kev: { version: string; released: string; count: number } | null;
    epss: { date: string; model: string } | null;
    links: "open" | "all" | "none";
    /** CVEs matched by component version against NVD and the kernel CNA; null when not run. */
    version_match?: { source: string; updated: string; years: number; matches: number } | null;
    /** Set when there is no SBOM: where the component list came from (rpm, opkg, dpkg, kernel only). */
    inventory?: string;
  };
  rows: CveRow[];
  /** Components with no product in NVD, so they couldn't be checked. Only without an SBOM. */
  unmapped?: { name: string; version: string }[];
}

export interface KernelEntry {
  subsystem: string;
  bucket: "harden" | "attack_surface";
  option: string;
  expect: string | { min: number };
  actual: string | null;
  status: "pass" | "fail" | "missing" | "na" | "accepted";
  why: string;
  ref: string;
  note: string;
}

export interface Report {
  tool: { name: string; version: string };
  image: { path: string; format: string; files: number; notes: string[] };
  summary: {
    findings: Partial<Record<Severity, number>>;
    scanned_at?: string;
    duration_s: number;
  };
  findings: Finding[];
  binaries: Binary[];
  fstab: { line: number; spec: string; mountpoint: string; fstype: string; options: string[]; missing?: string[] }[];
  sbom: null | {
    file: string;
    name: string;
    components: Record<string, number>;
    status_counts: Record<string, number>;
    graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  };
  kernel?: {
    source: { kind: string; path: string } | null;
    version: string;
    arch: string;
    entries: KernelEntry[];
    policy?: string | null;
    modules?: {
      mode: "enforced" | "checked" | "off" | "no-modules" | "unknown";
      config: Record<string, string | null>;
      items: {
        path: string; name: string; size: number; compressed?: boolean; signed: boolean | null;
        signature: { type: string; length: number } | null; vermagic: string; vermagic_match?: boolean;
        package: string;
      }[];
    };
  } | null;
  cves?: CveSection | null;
  overview?: { points: { topic: string; text: string }[]; model: string; label: string } | null;
}
