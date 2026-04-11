import { useState } from "react";
import { Loader2, Send } from "lucide-react";
import { toast } from "sonner";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { notificationService } from "@/services/api";

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
};

const categories = [
  { value: "general", label: "General" },
  { value: "access", label: "Access / accounts" },
  { value: "scan", label: "Scanning / data" },
  { value: "other", label: "Other" },
] as const;

export function ContactAdminSheet({ open, onOpenChange }: Props) {
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [category, setCategory] = useState<(typeof categories)[number]["value"]>("general");
  const [sending, setSending] = useState(false);

  const reset = () => {
    setSubject("");
    setBody("");
    setCategory("general");
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const s = subject.trim();
    const b = body.trim();
    if (!s || !b) {
      toast.error("Subject and message are required.");
      return;
    }
    setSending(true);
    try {
      await notificationService.send({ subject: s, body: b, category });
      toast.success("Message sent to administrators.");
      window.dispatchEvent(new Event("qs-notifications-updated"));
      reset();
      onOpenChange(false);
    } catch (err: unknown) {
      const ax = err as { response?: { data?: { detail?: string } } };
      toast.error(ax.response?.data?.detail || "Could not send message.");
    } finally {
      setSending(false);
    }
  };

  return (
    <Sheet
      open={open}
      onOpenChange={(o) => {
        if (!o) reset();
        onOpenChange(o);
      }}
    >
      <SheetContent className="w-full sm:max-w-md flex flex-col">
        <SheetHeader>
          <SheetTitle>Contact administrators</SheetTitle>
          <SheetDescription>
            This sends an in-app notification to QuantumShield admins. Use for access requests, scan issues, or other
            operational notes.
          </SheetDescription>
        </SheetHeader>
        <form onSubmit={handleSubmit} className="mt-4 flex flex-1 flex-col gap-4">
          <div className="space-y-1.5">
            <Label htmlFor="ncat">Category</Label>
            <select
              id="ncat"
              value={category}
              onChange={(e) => setCategory(e.target.value as (typeof categories)[number]["value"])}
              className="h-10 w-full rounded-md border border-border bg-secondary px-3 text-sm"
            >
              {categories.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="nsub">Subject</Label>
            <Input
              id="nsub"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              maxLength={200}
              placeholder="Short summary"
              className="bg-secondary"
            />
          </div>
          <div className="space-y-1.5 flex flex-1 flex-col min-h-[120px]">
            <Label htmlFor="nbody">Message</Label>
            <Textarea
              id="nbody"
              value={body}
              onChange={(e) => setBody(e.target.value)}
              maxLength={8000}
              placeholder="Describe what you need from admins…"
              className="bg-secondary flex-1 min-h-[140px] resize-y"
            />
          </div>
          <Button type="submit" disabled={sending} className="gap-2">
            {sending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
            Send to admins
          </Button>
        </form>
      </SheetContent>
    </Sheet>
  );
}
