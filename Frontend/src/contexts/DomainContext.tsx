import React, { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from "react";
import { reportingService } from "@/services/api";

interface DomainContextValue {
  /** The globally selected domain — all pages read from this */
  selectedDomain: string | null;
  /** Set the global domain (persisted in sessionStorage) */
  setSelectedDomain: (domain: string | null) => void;
  /** List of previously scanned domains (fetched once, refreshable) */
  availableDomains: string[];
  /** Refresh the domain list (call after a scan completes) */
  refreshDomains: () => void;
  /** True while the domain list is loading */
  loading: boolean;
}

const DomainContext = createContext<DomainContextValue>({
  selectedDomain: null,
  setSelectedDomain: () => {},
  availableDomains: [],
  refreshDomains: () => {},
  loading: false,
});

const STORAGE_KEY = "qs_selected_domain";

export function DomainProvider({ children }: { children: ReactNode }) {
  const [selectedDomain, _setSelectedDomain] = useState<string | null>(() => {
    try {
      return sessionStorage.getItem(STORAGE_KEY) || null;
    } catch {
      return null;
    }
  });
  const [availableDomains, setAvailableDomains] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  const setSelectedDomain = useCallback((domain: string | null) => {
    _setSelectedDomain(domain);
    try {
      if (domain) {
        sessionStorage.setItem(STORAGE_KEY, domain);
      } else {
        sessionStorage.removeItem(STORAGE_KEY);
      }
    } catch { /* ignore */ }
  }, []);

  const fetchDomains = useCallback(async () => {
    setLoading(true);
    try {
      const res = await reportingService.getDomains();
      const rows = Array.isArray(res.data) ? res.data : [];
      setAvailableDomains(rows.map((d: unknown) => String(d)).filter(Boolean));
    } catch {
      setAvailableDomains([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDomains();
  }, [fetchDomains]);

  return (
    <DomainContext.Provider
      value={{
        selectedDomain,
        setSelectedDomain,
        availableDomains,
        refreshDomains: fetchDomains,
        loading,
      }}
    >
      {children}
    </DomainContext.Provider>
  );
}

export function useDomain() {
  return useContext(DomainContext);
}
