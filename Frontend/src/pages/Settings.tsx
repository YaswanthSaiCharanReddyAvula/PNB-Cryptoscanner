import { DossierPageHeader } from "@/components/layout/DossierPageHeader";
import { useAuth } from "@/contexts/AuthContext";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useEffect, useState } from "react";

const REDUCED_MOTION_KEY = "quantumshield_reduced_motion";

export default function Settings() {
  const { user } = useAuth();
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    try {
      setReducedMotion(localStorage.getItem(REDUCED_MOTION_KEY) === "1");
    } catch {
      /* ignore */
    }
  }, []);

  const toggleMotion = (on: boolean) => {
    setReducedMotion(on);
    try {
      if (on) localStorage.setItem(REDUCED_MOTION_KEY, "1");
      else localStorage.removeItem(REDUCED_MOTION_KEY);
    } catch {
      /* ignore */
    }
    document.documentElement.dataset.reducedMotion = on ? "true" : "false";
  };

  return (
    <div className="space-y-8">
      <DossierPageHeader
        eyebrow="Account"
        title="Settings"
        description="Your profile comes from the signed-in session. Preferences below stay on this browser."
      />

      <div className="dossier-card p-6 max-w-xl space-y-6">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">Profile</h3>
          <dl className="mt-4 space-y-3 text-sm">
            <div>
              <dt className="text-xs text-muted-foreground">Display name</dt>
              <dd className="font-medium text-foreground">{user?.name || "—"}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Email</dt>
              <dd className="font-mono text-foreground">{user?.email || user?.username || "—"}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Role</dt>
              <dd className="font-medium text-foreground">{user?.role || "—"}</dd>
            </div>
          </dl>
        </div>

        <div className="border-t border-border pt-6">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">Accessibility</h3>
          <div className="mt-4 flex items-center justify-between gap-4">
            <div>
              <Label htmlFor="rm" className="text-sm font-normal">
                Reduce motion
              </Label>
              <p className="text-xs text-muted-foreground mt-1">
                Hint for the UI to prefer less animation (stored locally).
              </p>
            </div>
            <Switch id="rm" checked={reducedMotion} onCheckedChange={toggleMotion} />
          </div>
        </div>
      </div>
    </div>
  );
}
