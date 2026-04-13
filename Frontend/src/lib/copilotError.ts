import axios from "axios";
import { getViteApiBaseUrl } from "@/lib/runtimeConfig";

/** User-visible text when POST /ai/copilot/chat fails. */
export function formatCopilotRequestError(err: unknown): string {
  if (axios.isAxiosError(err)) {
    if (!err.response) {
      const hint = getViteApiBaseUrl();
      return (
        `Cannot reach the API (${hint}). ` +
        "Confirm the FastAPI backend is running, the URL matches this app (frontend .env VITE_API_BASE_URL), " +
        "and firewalls allow the browser to reach that host. " +
        "LM Studio is only used by the backend after the request succeeds."
      );
    }
    const status = err.response.status;
    const data = err.response.data as { detail?: string | unknown[]; error?: string };
    let detail = "";
    if (typeof data?.detail === "string") {
      detail = data.detail;
    } else if (Array.isArray(data?.detail)) {
      detail = data.detail
        .map((x) => {
          if (x && typeof x === "object" && "msg" in x) return String((x as { msg: string }).msg);
          return String(x);
        })
        .join("; ");
    }
    if (status === 401) {
      return "Your session expired or you are not signed in. Sign in again.";
    }
    if (status === 503) {
      return detail ? `Service unavailable: ${detail}` : "Service unavailable (e.g. database not connected).";
    }
    if (status >= 500) {
      return detail
        ? `Server error (${status}): ${detail}`
        : `Server error (${status}). Check backend logs.`;
    }
    return detail || `Request failed (${status}).`;
  }
  return err instanceof Error ? err.message : "Unknown error.";
}
