import { Check, ShieldAlert, ShieldCheck, ShieldOff, X } from "lucide-react";
import { useState, type ReactNode } from "react";
import type { Report } from "../types";
import { Dropdown, PageHead, usePage } from "../ui";

type Mode = NonNullable<NonNullable<Report["kernel"]>["modules"]>["mode"];

function headline(mode: Mode): { text: string; cls: string; icon: ReactNode } {
  if (mode === "enforced") return { text: "Kernel only allows signed modules to load", cls: "mode-good", icon: <ShieldCheck size={15} /> };
  if (mode === "no-modules") return { text: "Kernel is built without loadable module support", cls: "mode-good", icon: <ShieldCheck size={15} /> };
  if (mode === "unknown") return { text: "No kernel config found, so signature enforcement can't be told", cls: "mode-unknown", icon: <ShieldAlert size={15} /> };
  return { text: "An attacker can load unsigned modules as signature checks aren't enforced", cls: "mode-bad", icon: <ShieldOff size={15} /> };
}

const EXPLAIN: Record<string, { on: string; off: string }> = {
  MODULE_SIG: {
    on: "The kernel checks each module's signature when it loads; unsigned modules taint the kernel.",
    off: "Enable it so the kernel checks each module's signature when it loads.",
  },
  MODULE_SIG_FORCE: {
    on: "Modules without a valid signature are refused, even when root loads them.",
    off: "Enable it so unsigned or tampered modules are refused instead of loaded; needs MODULE_SIG.",
  },
};

/** One signing option as a compact value; what it means is in the tooltip. */
function Opt({ name, value }: { name: string; value: string | null | undefined }) {
  const on = value === "y";
  const raw = value === "y" ? "=y" : value === "n" ? "is not set" : value ? `=${value}` : "absent (its dependencies are off)";
  return (
    <span className="kopt" title={`CONFIG_${name} ${raw}. ${on ? EXPLAIN[name].on : EXPLAIN[name].off}`}>
      <code>CONFIG_{name}</code><span className={`kopt-v ${on ? "on" : "off"}`}>{on ? "on" : "off"}</span>
    </span>
  );
}

function size(n: number) {
  return n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`;
}

export default function Modules({ r }: { r: Report }) {
  const m = r.kernel?.modules;
  const items = m?.items ?? [];
  const [signed, setSigned] = useState("");

  const head = headline(m?.mode ?? "unknown");
  const shown = items.filter((x) => signed === "" || (signed === "signed" ? x.signed === true : x.signed !== true));
  const page = usePage(shown, signed);
  const signedOpts = [
    { value: "", label: "All", n: items.length },
    { value: "signed", label: "Signed", n: items.filter((x) => x.signed === true).length },
    { value: "unsigned", label: "Unsigned", n: items.length - items.filter((x) => x.signed === true).length },
  ];
  return (
    <div className="grid">
      <section className="card span-12">
        <PageHead title="Modules"
          note={<>
            <span className={`mod-warn ${head.cls}`}>{head.icon}<span>{head.text}</span></span>
            {m && (m.mode === "enforced" || m.mode === "checked" || m.mode === "off") && <>
              <span className="note-sep">·</span>
              <Opt name="MODULE_SIG" value={m.config.MODULE_SIG} />
              <Opt name="MODULE_SIG_FORCE" value={m.config.MODULE_SIG_FORCE} />
            </>}
          </>}
          />
      </section>

      <section className="card span-12">
        {items.length === 0 ? <div className="empty">No kernel modules (<code>.ko</code>) in the image.</div> : (
          <>
          <div className="toolbar">
            <Dropdown label="Signed" value={signed} options={signedOpts} onChange={setSigned} />
            <span className="spacer" />
            <span className="muted">{shown.length} of {items.length}</span>
          </div>
          <table className="kt">
            <thead>
              <tr><th>Module</th><th>Package</th><th>Size</th><th className="c">Signed</th><th>Built for</th></tr>
            </thead>
            <tbody ref={page.bodyRef}>
              {page.rows.map((x) => (
                <tr key={x.path}>
                  <td><code>{x.name}</code>
                    <div className="muted kt-why">{x.path}</div>
                    {x.signature && <div className="muted kt-why">{x.signature.type} · {x.signature.length} bytes</div>}
                  </td>
                  <td>{x.package ? <code>{x.package}</code> : <span className="muted">–</span>}</td>
                  <td className="nowrap num">{size(x.size)}{x.compressed && <span className="muted"> · compressed</span>}</td>
                  <td className="c">
                    {x.signed === null ? <span className="muted" title="Couldn't read the module">?</span>
                      : x.signed ? <Check size={16} className="ink2" aria-label="signed" /> : <X size={16} className="no" aria-label="unsigned" />}
                  </td>
                  <td>
                    <code className="muted" title={x.vermagic}>{x.vermagic.split(" ")[0] || "–"}</code>
                    {x.vermagic && x.vermagic_match === false && <div className="no kt-why">doesn't match the kernel</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {page.pager}
          </>
        )}
      </section>
    </div>
  );
}
