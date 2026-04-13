/// <reference types="vite/client" />

interface Window {
  electronAPI?: { platform: string; apiBaseUrl?: string | null };
}
