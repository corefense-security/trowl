import { TriangleAlert } from "lucide-react";
import type { Finding, Report } from "../types";
import { PageHead, usePage } from "../ui";

type Mount = Report["fstab"][number];

/** What each secure mount flag stops. */
const FLAGS: [string, string][] = [
  ["ro", "read-only"],
  ["nosuid", "setuid and setgid bits are ignored"],
  ["nodev", "device files can't be created or opened"],
  ["noexec", "non-executable, prevents malicious code execution"],
  ["hidepid", "=1 restricts access to other users' /proc entries\n=2 hides them entirely"],
];

/** The fstab mount point that holds this path (longest prefix), or "/" if none matches. */
function mountOf(path: string, mounts: Mount[]): string {
  let best = "/";
  for (const m of mounts) {
    const mp = m.mountpoint.replace(/\/+$/, "") || "/";
    if ((mp === "/" || path === mp || path.startsWith(mp + "/")) && mp.length > best.length) best = mp;
  }
  return best;
}

function detail(f: Finding) {
  const e = f.evidence as { encrypted?: boolean; preview?: string; sha256?: string };
  const parts = [];
  if (e.sha256) parts.push(<code key="h" title={`SHA-256 of the match: ${e.sha256}`}>{e.sha256.slice(0, 12)}…</code>);
  if (f.detail) parts.push(<span key="d" className="muted">{f.detail}</span>);
  return parts.length ? <span className="fs-detail">{parts}</span> : <span className="muted">–</span>;
}

export default function Filesystems({ r }: { r: Report }) {
  const secrets = r.findings.filter((f) => f.check.startsWith("secrets."));
  const byMount = new Map<string, Finding[]>();
  for (const f of secrets) {
    const m = mountOf(f.path, r.fstab);
    byMount.set(m, [...(byMount.get(m) ?? []), f]);
  }

  const mountPage = usePage(r.fstab, null, true);
  const secretRows = [...byMount.entries()].sort(([a], [b]) => a.localeCompare(b)).flatMap(([, fs]) => fs.map((f, i) => ({ f, i })));
  const secretPage = usePage(secretRows, null, true);

  return (
    <div className="grid">
      <section className="card span-12">
        <PageHead title="Mount flags" note={<>Read from <code>/etc/fstab</code></>} />
        {r.fstab.length === 0 ? <div className="empty">No fstab entries.</div> : (<>
          <div className="fs-legend">{FLAGS.map(([f, what]) => <div key={f}><code>{f}</code>{what}</div>)}</div>
          <table className="mounts">
            <colgroup>
              <col style={{ width: "20%" }} /><col style={{ width: "14%" }} /><col style={{ width: "22%" }} /><col /><col className="flag" />
            </colgroup>
            <thead>
              <tr>
                <th>Mount point</th><th>Type</th><th>Device</th>
                <th title="Secure mount flags this mount lacks">Missing</th>
                <th className="c" title="Private keys and tokens found under this mount point">Secrets</th>
              </tr>
            </thead>
            <tbody ref={mountPage.bodyRef}>
              {mountPage.rows.map((e) => {
                const missing = e.missing ?? [];
                const n = byMount.get(e.mountpoint.replace(/\/+$/, "") || "/")?.length ?? 0;
                return (
                  <tr key={e.line}>
                    <td><code>{e.mountpoint}</code></td>
                    <td>{e.fstype}</td>
                    <td className="ink2 ellipsis" title={e.spec}>{e.spec}</td>
                    <td title={`Options: ${e.options.join(",")}`}>{missing.length
                      ? <span className="fs-missing"><TriangleAlert size={14} /><span>add: {missing.map((m, i) => <span key={m}>{i > 0 && ", "}<code>{m}</code></span>)}</span></span>
                      : <span className="muted">–</span>}</td>
                    <td className="c">{n ? <b className="no num">{n}</b> : <span className="muted">–</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {mountPage.pager}
        </>)}
      </section>

      <section className="card span-12">
        <PageHead title="Secrets and keys"
          note={secrets.length ? `${secrets.length} found across ${byMount.size} mount point${byMount.size === 1 ? "" : "s"}` : `${r.image.files.toLocaleString()} files checked`} />
        {secrets.length === 0 ? (
          <div className="fs-none">
            <b>No private keys, baked-in host keys or tokens found.</b>
            <div className="muted">Checked for PEM, OpenSSH and PuTTY private keys, SSH and Dropbear host keys shipped in the image, and AWS, GitHub, GitLab, Slack and Google tokens.</div>
          </div>
        ) : (<>
          <table>
            <thead><tr><th>Path</th><th>What</th><th>Hash</th></tr></thead>
            <tbody ref={secretPage.bodyRef}>
              {secretPage.rows.map(({ f, i }) => (
                  <tr key={`${f.path}:${f.title}:${i}`}>
                    <td><code>{f.path}</code></td>
                    <td>{f.title}</td>
                    <td>{detail(f)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
          {secretPage.pager}
        </>)}
      </section>
    </div>
  );
}
