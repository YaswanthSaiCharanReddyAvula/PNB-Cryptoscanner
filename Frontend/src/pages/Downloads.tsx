import { useMemo, useState } from "react";
import { DossierPageHeader } from "@/components/layout/DossierPageHeader";
import { APP_NAME } from "@/lib/appMeta";
import { Copy, Download, ExternalLink, ShieldCheck } from "lucide-react";

const WINDOWS_INSTALLER_NAME = "QuantumShield-Setup-1.0.0.exe";
const WINDOWS_INSTALLER_VERSION = "1.0.0";
const WINDOWS_INSTALLER_SIZE = "145 MB";
const WINDOWS_INSTALLER_SHA256 = "REPLACE_WITH_REAL_SHA256_HASH";

export default function DownloadsPage() {
  const [copied, setCopied] = useState(false);

  const windowsDownloadUrl = useMemo(() => {
    const fromEnv = import.meta.env.VITE_WINDOWS_EXE_URL?.trim();
    return fromEnv || "http://51.20.189.203/downloads/QuantumShield-Setup-1.0.0.exe";
  }, []);

  const handleCopyHash = async () => {
    try {
      await navigator.clipboard.writeText(WINDOWS_INSTALLER_SHA256);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="space-y-8">
      <DossierPageHeader
        eyebrow="Distribution"
        title="Downloads"
        description={`Download the latest signed desktop installer for ${APP_NAME}. Verify integrity before rollout across your teams.`}
      />

      <section className="dossier-card max-w-4xl p-6 md:p-8">
        <div className="flex flex-col gap-6 md:flex-row md:items-start md:justify-between">
          <div className="space-y-3">
            <div className="inline-flex items-center gap-2 rounded-full border border-border/80 bg-muted/40 px-3 py-1 text-xs font-medium text-muted-foreground">
              <ShieldCheck className="h-3.5 w-3.5" />
              Production release
            </div>
            <div>
              <h2 className="text-xl font-semibold text-slate-900">{WINDOWS_INSTALLER_NAME}</h2>
              <p className="mt-1 text-sm text-slate-600">
                Version {WINDOWS_INSTALLER_VERSION} · {WINDOWS_INSTALLER_SIZE} · Windows x64
              </p>
            </div>
            <p className="max-w-2xl text-sm leading-relaxed text-slate-600">
              Use this package for enterprise rollout. The installer targets the desktop client and connects to
              your hosted backend endpoint configured in runtime settings.
            </p>
          </div>

          <a
            href={windowsDownloadUrl}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-sidebar-primary px-4 py-2.5 text-sm font-semibold text-sidebar-primary-foreground transition-opacity hover:opacity-90"
          >
            <Download className="h-4 w-4" />
            Download .exe
          </a>
        </div>

        <div className="mt-8 space-y-3 rounded-lg border border-border/80 bg-muted/30 p-4">
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">SHA-256</p>
          <p className="break-all rounded-md bg-background/80 px-3 py-2 font-mono text-xs text-slate-700">
            {WINDOWS_INSTALLER_SHA256}
          </p>
          <button
            type="button"
            onClick={handleCopyHash}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-primary hover:underline"
          >
            <Copy className="h-3.5 w-3.5" />
            {copied ? "Hash copied" : "Copy hash"}
          </button>
        </div>

        <div className="mt-6 grid gap-4 text-sm text-slate-600 md:grid-cols-2">
          <div className="rounded-lg border border-border/70 p-4">
            <h3 className="font-semibold text-slate-900">Install notes</h3>
            <ul className="mt-2 list-disc space-y-1 pl-5">
              <li>Run as a standard user unless policy requires elevation.</li>
              <li>Keep antivirus/EDR active during installation.</li>
              <li>Validate endpoint reachability from your network before rollout.</li>
            </ul>
          </div>
          <div className="rounded-lg border border-border/70 p-4">
            <h3 className="font-semibold text-slate-900">Release operations</h3>
            <p className="mt-2">
              Host installers under a stable URL (for example, <span className="font-mono">/downloads</span>) and
              rotate versioned files on each release.
            </p>
            <a
              href={windowsDownloadUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-3 inline-flex items-center gap-1.5 text-primary hover:underline"
            >
              Open file URL
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          </div>
        </div>
      </section>
    </div>
  );
}
