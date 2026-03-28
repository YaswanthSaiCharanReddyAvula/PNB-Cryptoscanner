import { useEffect, useState } from "react";
import { DossierPageHeader } from "@/components/layout/DossierPageHeader";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/contexts/AuthContext";
import { adminService } from "@/services/api";
import { toast } from "sonner";
import { Loader2, Shield } from "lucide-react";

export default function PolicyStandards() {
  const { user } = useAuth();
  const isAdmin = user?.role === "Admin";

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [minTls, setMinTls] = useState("1.3");
  const [strict, setStrict] = useState(true);
  const [pqcKem, setPqcKem] = useState("ml-kem-768");
  const [pqcSig, setPqcSig] = useState("ml-dsa-65");
  const [notes, setNotes] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const res = await adminService.getPolicy();
        const pol = res.data;
        if (pol && !cancelled) {
          setMinTls(pol.min_tls_version || "1.3");
          setStrict(!!pol.require_forward_secrecy);
          setNotes(String(pol.policy_notes || ""));
          const raw = String(pol.pqc_readiness_target || "");
          if (raw.includes("·")) {
            const [a, b] = raw.split("·").map((s: string) => s.trim());
            const kems = ["ml-kem-512", "ml-kem-768", "ml-kem-1024"] as const;
            const sigs = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"] as const;
            if (kems.includes(a as (typeof kems)[number])) setPqcKem(a);
            if (sigs.includes(b as (typeof sigs)[number])) setPqcSig(b);
          }
        }
      } catch {
        toast.error("Could not load policy.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const save = async () => {
    if (!isAdmin) {
      toast.message("Admin role required to save policy.");
      return;
    }
    setSaving(true);
    try {
      await adminService.putPolicy({
        min_tls_version: minTls,
        require_forward_secrecy: strict,
        pqc_readiness_target: `${pqcKem} · ${pqcSig}`,
        policy_notes: notes.trim(),
      });
      toast.success("Policy updated");
    } catch {
      toast.error("Save failed");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-8">
      <DossierPageHeader
        eyebrow="Governance"
        title="Policy & Standards"
        description="Define cryptographic boundaries for your organization. Targets map to org policy stored in QuantumShield."
      />

      {loading ? (
        <div className="flex items-center gap-2 text-slate-500">
          <Loader2 className="h-5 w-5 animate-spin" />
          Loading policy…
        </div>
      ) : (
        <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
          <div className="space-y-6">
            <section className="dossier-card p-6">
              <div className="mb-4 flex items-center gap-2">
                <Shield className="h-5 w-5 text-slate-700" />
                <h2 className="text-lg font-semibold text-slate-900">Transport layer standards</h2>
              </div>
              <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-2">
                  <Label className="text-xs font-semibold uppercase text-slate-500">
                    Minimum TLS version
                  </Label>
                  <Select value={minTls} onValueChange={setMinTls} disabled={!isAdmin}>
                    <SelectTrigger className="bg-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1.2">TLS 1.2</SelectItem>
                      <SelectItem value="1.3">TLS 1.3</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label className="text-xs font-semibold uppercase text-slate-500">
                    Policy strictness
                  </Label>
                  <div className="flex h-10 items-center justify-between rounded-md border border-slate-200 px-3">
                    <span className="text-sm text-slate-700">Enforce forward secrecy</span>
                    <Switch checked={strict} onCheckedChange={setStrict} disabled={!isAdmin} />
                  </div>
                </div>
              </div>
            </section>

            <section className="dossier-card p-6">
              <h2 className="mb-4 text-lg font-semibold text-slate-900">
                Post-quantum cryptography (targets)
              </h2>
              <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-2">
                  <Label className="text-xs font-semibold uppercase text-slate-500">
                    Primary KEM target
                  </Label>
                  <Select value={pqcKem} onValueChange={setPqcKem} disabled={!isAdmin}>
                    <SelectTrigger className="bg-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ml-kem-512">ML-KEM-512</SelectItem>
                      <SelectItem value="ml-kem-768">Kyber-768 (ML-KEM)</SelectItem>
                      <SelectItem value="ml-kem-1024">ML-KEM-1024</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label className="text-xs font-semibold uppercase text-slate-500">
                    Signature scheme
                  </Label>
                  <Select value={pqcSig} onValueChange={setPqcSig} disabled={!isAdmin}>
                    <SelectTrigger className="bg-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ml-dsa-44">ML-DSA-44</SelectItem>
                      <SelectItem value="ml-dsa-65">Dilithium-Level 3 (ML-DSA)</SelectItem>
                      <SelectItem value="ml-dsa-87">ML-DSA-87</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </section>

            <section className="dossier-card p-6">
              <Label className="text-xs font-semibold uppercase text-slate-500">Policy notes</Label>
              <Textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                disabled={!isAdmin}
                className="mt-2 min-h-[100px] border-slate-200 bg-white"
                placeholder="Executive notes, exceptions, rollout phases…"
              />
            </section>

            {isAdmin && (
              <Button
                onClick={save}
                disabled={saving}
                className="rounded-lg bg-slate-900 text-white hover:bg-slate-800"
              >
                {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Apply changes
              </Button>
            )}
          </div>

          <aside className="space-y-4">
            <div className="rounded-xl bg-slate-900 p-5 text-white shadow-lg">
              <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">
                Policy impact preview
              </p>
              <p className="mt-3 text-3xl font-bold">Fleet-wide</p>
              <p className="mt-2 text-sm leading-relaxed text-slate-300">
                Saving updates org defaults used by reporting and migration backlog seeding.
              </p>
            </div>
            <div className="dossier-card p-4">
              <p className="text-sm font-medium text-slate-900">Quick recommendation</p>
              <p className="mt-2 text-sm text-slate-600">
                Pair TLS 1.3 with hybrid KEM pilots on external gateways before legacy partner cutovers.
              </p>
            </div>
          </aside>
        </div>
      )}
    </div>
  );
}
