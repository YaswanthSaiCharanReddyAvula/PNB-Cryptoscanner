import { DossierPageHeader } from "@/components/layout/DossierPageHeader";
import { APP_NAME, APP_VERSION } from "@/lib/appMeta";
import { ExternalLink } from "lucide-react";

export default function About() {
  const version = APP_VERSION;
  const name = APP_NAME;

  return (
    <div className="space-y-8">
      <DossierPageHeader
        eyebrow="Help"
        title="About"
        description="QuantumShield — quantum-safe migration and cryptographic posture visibility for your organization."
      />

      <div className="dossier-card p-6 max-w-2xl space-y-4 text-sm text-foreground">
        <p>
          <span className="font-semibold">App:</span> {name}{" "}
          <span className="font-mono text-muted-foreground">v{version}</span>
        </p>
        <p className="text-muted-foreground leading-relaxed">
          This interface connects to the QuantumShield backend for discovery, TLS assessment, CBOM, quantum risk scoring,
          and migration planning. Scan results are indicative; validate with your security and PKI teams before
          production or compliance commitments.
        </p>
        <div className="flex flex-wrap gap-3 pt-2">
          <a
            href="https://github.com"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-primary hover:underline text-sm font-medium"
          >
            Documentation <ExternalLink className="h-3.5 w-3.5" />
          </a>
        </div>
      </div>
    </div>
  );
}
