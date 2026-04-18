import { useEffect, useState } from "react";
import { useParams, useSearchParams, Link } from "react-router-dom";
import {
  Shield, Globe, Server, Lock, AlertTriangle, CheckCircle2,
  XCircle, ChevronDown, ChevronRight, Network, FileText,
  Cpu, Wifi, Eye, Clock, Hash, ExternalLink, RefreshCw,
  Monitor, Radio
} from "lucide-react";
import { scanService } from "@/services/api";
import { useDomain } from "@/contexts/DomainContext";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import html2canvas from "html2canvas";
import jsPDF from "jspdf";

/* ── helpers ── */
const fmtDate = (v: unknown) =>
  v ? new Date(String(v)).toLocaleString() : "—";

const riskColor = (r: string) => {
  const v = (r || "").toLowerCase();
  if (v === "critical") return "bg-red-100 text-red-800 border-red-200";
  if (v === "high") return "bg-orange-100 text-orange-800 border-orange-200";
  if (v === "medium") return "bg-yellow-100 text-yellow-800 border-yellow-200";
  if (v === "low") return "bg-green-100 text-green-800 border-green-200";
  return "bg-slate-100 text-slate-700 border-slate-200";
};

const strengthColor = (s: string) => {
  const v = (s || "").toLowerCase();
  if (v === "insecure") return "text-red-600";
  if (v === "weak") return "text-orange-500";
  if (v === "acceptable") return "text-yellow-600";
  if (v === "strong") return "text-green-600";
  return "text-slate-500";
};

/* ── tiny collapsible section ── */
function Section({ title, icon: Icon, count, children, defaultOpen = false }: {
  title: string; icon: any; count?: number; children: React.ReactNode; defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-xl border border-slate-200 overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 bg-slate-50 hover:bg-slate-100 transition-colors"
      >
        <span className="flex items-center gap-2 font-semibold text-sm text-slate-800">
          <Icon className="h-4 w-4 text-primary" />
          {title}
          {count !== undefined && (
            <span className="ml-1 rounded-full bg-primary/10 text-primary px-2 py-0.5 text-xs font-bold">{count}</span>
          )}
        </span>
        {open ? <ChevronDown className="h-4 w-4 text-slate-400" /> : <ChevronRight className="h-4 w-4 text-slate-400" />}
      </button>
      {open && <div className="p-4 space-y-3">{children}</div>}
    </div>
  );
}

/* ── kv row ── */
const KV = ({ label, value }: { label: string; value: React.ReactNode }) => (
  <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-sm">
    <span className="w-40 shrink-0 text-slate-500 font-medium">{label}</span>
    <span className="text-slate-900 font-mono break-all">{value ?? "—"}</span>
  </div>
);

export default function ScanResults() {
  const { selectedDomain } = useDomain();
  const { domain: paramDomain } = useParams<{ domain: string }>();
  const [searchParams] = useSearchParams();
  const domain = paramDomain || searchParams.get("domain") || selectedDomain || "";

  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = async () => {
    if (!domain) return;
    setLoading(true); setError("");
    try {
      const res = await scanService.getScanDetails(domain);
      setData(res.data);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to load scan results");
    } finally { setLoading(false); }
  };

  const downloadPDF = async () => {
    const element = document.getElementById("scan-results-content");
    const btnContainer = document.getElementById("action-buttons");
    if (!element) return;
    
    // Hide buttons during capture
    if (btnContainer) btnContainer.style.display = "none";
    
    try {
      const canvas = await html2canvas(element, { scale: 2, useCORS: true, backgroundColor: "#ffffff" });
      const imgData = canvas.toDataURL("image/jpeg", 1.0);
      const pdf = new jsPDF("p", "mm", "a4");
      
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = (canvas.height * pdfWidth) / canvas.width;
      const pageHeight = pdf.internal.pageSize.getHeight();
      
      let position = 0;
      let heightLeft = pdfHeight;
      
      pdf.addImage(imgData, "JPEG", 0, position, pdfWidth, pdfHeight);
      heightLeft -= pageHeight;
      
      while (heightLeft > 0) {
        position -= pageHeight;
        pdf.addPage();
        pdf.addImage(imgData, "JPEG", 0, position, pdfWidth, pdfHeight);
        heightLeft -= pageHeight;
      }
      
      pdf.save(`ScanResults_${domain}.pdf`);
    } catch (e) {
      console.error("PDF generation failed", e);
    } finally {
      if (btnContainer) btnContainer.style.display = "flex";
    }
  };

  useEffect(() => { load(); }, [domain]);

  if (!domain) return <div className="p-8 text-slate-500">No domain specified.</div>;
  if (loading) return (
    <div className="flex items-center justify-center h-64 gap-3 text-slate-500">
      <RefreshCw className="h-5 w-5 animate-spin" /> Loading scan results…
    </div>
  );
  if (error) return <div className="p-8 text-red-600">{error}</div>;
  if (!data) return <div className="p-8 text-slate-500">No data found.</div>;

  const recon = data.recon_full || {};
  const subdomains: string[] = data.subdomains || recon.subdomains || [];
  const dnsRecords: any[] = data.dns_records || recon.dns_records || [];
  const tlsResults: any[] = data.tls_results || [];
  const cbom: any[] = data.cbom || [];
  const cdnWaf: any[] = data.cdn_waf_intel || [];
  const techFp: any[] = data.tech_fingerprints || [];
  const webProfiles: any[] = data.web_profiles || [];
  const vuln: any[] = data.vuln_findings || [];
  const cve: any[] = data.cve_findings || [];
  const qs = data.quantum_score || {};
  const whois = recon.whois || {};
  const ipMap: Record<string, string[]> = recon.ip_map || {};
  const ctHosts: string[] = recon.ct_hosts || [];
  const reverseDns: Record<string, string> = recon.reverse_dns || {};
  const osFp: any[] = data.os_fingerprints || [];
  const services: any[] = data.services || [];

  return (
    <div id="scan-results-content" className="space-y-5 pb-16 bg-transparent">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-widest font-semibold mb-1">Scan Results</p>
          <h1 className="text-2xl font-bold text-slate-900 font-mono">{domain}</h1>
          <div className="flex flex-wrap gap-2 mt-2">
            <span className={`text-xs px-2 py-0.5 rounded border font-semibold ${
              data.status === "completed" ? "bg-emerald-50 text-emerald-700 border-emerald-200"
              : data.status === "failed" ? "bg-red-50 text-red-700 border-red-200"
              : "bg-blue-50 text-blue-700 border-blue-200"
            }`}>{(data.status || "unknown").toUpperCase()}</span>
            {qs.risk_level && (
              <span className={`text-xs px-2 py-0.5 rounded border font-semibold ${riskColor(qs.risk_level)}`}>
                Quantum Risk: {qs.risk_level}
              </span>
            )}
            {qs.score !== undefined && (
              <span className="text-xs px-2 py-0.5 rounded border bg-violet-50 text-violet-700 border-violet-200 font-semibold">
                Score: {typeof qs.score === "number" ? qs.score.toFixed(1) : qs.score}
              </span>
            )}
          </div>
        </div>
        <div id="action-buttons" className="flex gap-2 flex-wrap no-print">
          <Button size="sm" variant="outline" onClick={load}>
            <RefreshCw className="h-3.5 w-3.5 mr-1" /> Refresh
          </Button>
          <Button size="sm" variant="outline" onClick={downloadPDF}>
            <FileText className="h-3.5 w-3.5 mr-1" /> Download PDF
          </Button>
          <Button size="sm" variant="outline" asChild>
            <Link to="/inventory-runs"><ExternalLink className="h-3.5 w-3.5 mr-1" />All Scans</Link>
          </Button>
        </div>
      </div>

      {/* Timing */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: "Started", value: fmtDate(data.started_at) },
          { label: "Completed", value: fmtDate(data.completed_at) },
          { label: "Subdomains", value: subdomains.length },
          { label: "Services", value: services.length },
          { label: "Crypto Findings", value: cbom.length },
          { label: "OS Detected", value: osFp.filter((o: any) => o.os_family).length + "/" + osFp.length },
        ].map(s => (
          <div key={s.label} className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
            <p className="text-xs text-slate-500 font-medium">{s.label}</p>
            <p className="text-lg font-bold text-slate-900 mt-0.5">{s.value}</p>
          </div>
        ))}
      </div>

      {/* ── 1. Subdomains ── */}
      <Section title="Discovered Subdomains" icon={Globe} count={subdomains.length} defaultOpen>
        {subdomains.length === 0 ? <p className="text-sm text-slate-400">None found.</p> : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {subdomains.map((h: string) => (
              <div key={h} className="flex items-center gap-2 rounded-lg border border-slate-100 bg-white px-3 py-2">
                <Globe className="h-3.5 w-3.5 text-blue-500 shrink-0" />
                <span className="font-mono text-sm text-slate-800 break-all">{h}</span>
                {ipMap[h] && (
                  <span className="ml-auto text-xs text-slate-400 font-mono">{ipMap[h][0]}</span>
                )}
              </div>
            ))}
          </div>
        )}
        {ctHosts.length > 0 && (
          <details className="mt-2">
            <summary className="text-xs text-slate-500 cursor-pointer">CT Log hosts ({ctHosts.length})</summary>
            <div className="mt-2 flex flex-wrap gap-1">
              {ctHosts.map(h => (
                <span key={h} className="font-mono text-xs bg-slate-100 px-2 py-0.5 rounded">{h}</span>
              ))}
            </div>
          </details>
        )}
      </Section>

      {/* ── 2. DNS Records ── */}
      <Section title="DNS Records" icon={Network} count={dnsRecords.length} defaultOpen>
        {dnsRecords.length === 0 ? <p className="text-sm text-slate-400">No records.</p> : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-100">
                  {["Type","Name","Value","TTL"].map(h => (
                    <th key={h} className="text-left py-1.5 pr-4 font-semibold text-slate-500 uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {dnsRecords.map((r: any, i: number) => (
                  <tr key={i} className="border-b border-slate-50 hover:bg-slate-50">
                    <td className="py-1.5 pr-4 font-mono font-bold text-blue-600">{r.record_type}</td>
                    <td className="py-1.5 pr-4 font-mono text-slate-700">{r.name || domain}</td>
                    <td className="py-1.5 pr-4 font-mono text-slate-800 break-all max-w-xs">{r.value}</td>
                    <td className="py-1.5 text-slate-400">{r.ttl ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {/* ── 3. IP Map + Reverse DNS ── */}
      {Object.keys(ipMap).length > 0 && (
        <Section title="IP Address Map" icon={Server} count={Object.keys(ipMap).length}>
          <div className="space-y-2">
            {Object.entries(ipMap).map(([host, ips]) => (
              <div key={host} className="flex flex-wrap gap-2 items-center text-sm rounded-lg border border-slate-100 px-3 py-2">
                <span className="font-mono font-semibold text-slate-800 w-52 shrink-0">{host}</span>
                <span className="text-slate-400 text-xs">→</span>
                <span className="font-mono text-slate-600">{(ips as string[]).join(", ")}</span>
                {reverseDns[ips[0]] && (
                  <span className="ml-auto text-xs text-slate-400 font-mono">PTR: {reverseDns[ips[0]]}</span>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── 3b. Network Services ── */}
      {services.length > 0 && (
        <Section title="Network Services" icon={Radio} count={services.length}>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-100">
                  {["Host","Port","State","Service","Product","Version","Protocol","Confidence"].map(h => (
                    <th key={h} className="text-left py-1.5 pr-3 font-semibold text-slate-500 uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {services.map((s: any, i: number) => (
                  <tr key={i} className="border-b border-slate-50 hover:bg-slate-50">
                    <td className="py-1.5 pr-3 font-mono text-slate-700">{s.host}</td>
                    <td className="py-1.5 pr-3">
                      <span className="font-mono font-bold text-blue-700">{s.port}</span>
                    </td>
                    <td className="py-1.5 pr-3">
                      <span className={`px-1.5 py-0.5 rounded text-xs font-semibold ${
                        s.state === "open" ? "bg-green-50 text-green-700 border border-green-200"
                        : "bg-red-50 text-red-700 border border-red-200"
                      }`}>{s.state}</span>
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-slate-800">{s.service_name || "—"}</td>
                    <td className="py-1.5 pr-3 text-slate-600">{s.product || "—"}</td>
                    <td className="py-1.5 pr-3 font-mono text-slate-600">{s.version || "—"}</td>
                    <td className="py-1.5 pr-3">
                      <span className={`px-1.5 py-0.5 rounded border text-xs ${
                        s.protocol_category === "web" ? "bg-blue-50 text-blue-700 border-blue-200"
                        : s.protocol_category === "remote" ? "bg-violet-50 text-violet-700 border-violet-200"
                        : s.protocol_category === "mail" ? "bg-amber-50 text-amber-700 border-amber-200"
                        : "bg-slate-50 text-slate-600 border-slate-200"
                      }`}>{s.protocol_category || "other"}</span>
                    </td>
                    <td className="py-1.5 pr-3 text-slate-400">{s.confidence || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {/* Show SSH banners if any */}
          {services.filter((s: any) => s.raw_banner && (s.service_name || "").toLowerCase().includes("ssh")).length > 0 && (
            <details className="mt-2">
              <summary className="text-xs text-slate-500 cursor-pointer font-semibold">SSH Banners</summary>
              <div className="mt-2 space-y-1">
                {services.filter((s: any) => s.raw_banner && (s.service_name || "").toLowerCase().includes("ssh")).map((s: any, i: number) => (
                  <div key={i} className="font-mono text-xs bg-slate-900 text-green-400 px-3 py-1.5 rounded-lg">
                    {s.host}:{s.port} → {(s.raw_banner || "").trim()}
                  </div>
                ))}
              </div>
            </details>
          )}
        </Section>
      )}

      {/* ── 3c. OS Fingerprints ── */}
      {osFp.length > 0 && (
        <Section title="OS Fingerprints" icon={Monitor} count={osFp.length}>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {osFp.map((o: any, i: number) => {
              const confColor = o.os_confidence === "high" ? "bg-green-50 text-green-700 border-green-200"
                : o.os_confidence === "medium" ? "bg-yellow-50 text-yellow-700 border-yellow-200"
                : "bg-slate-50 text-slate-500 border-slate-200";
              return (
                <div key={i} className="rounded-xl border border-slate-200 p-3 space-y-1.5">
                  <p className="font-mono font-bold text-slate-800 text-sm">{o.host}</p>
                  <KV label="OS Family" value={
                    o.os_family
                      ? <span className="font-semibold text-blue-700">{o.os_family}</span>
                      : <span className="text-slate-400 italic">Unknown</span>
                  } />
                  <KV label="OS Version" value={
                    o.os_version
                      ? <span className="font-mono">{o.os_version}</span>
                      : <span className="text-slate-400 italic">—</span>
                  } />
                  <KV label="Confidence" value={
                    <span className={`px-1.5 py-0.5 rounded border text-xs font-semibold ${confColor}`}>
                      {o.os_confidence}
                    </span>
                  } />
                  {o.runtime && <KV label="Runtime" value={
                    <span className="font-mono text-violet-700">{o.runtime}</span>
                  } />}
                  <KV label="Container" value={
                    o.container_likely
                      ? <span className="text-orange-600 font-semibold">⚡ Likely containerized</span>
                      : <span className="text-slate-400">No</span>
                  } />
                  {o.evidence_sources?.length > 0 && (
                    <p className="text-xs text-slate-400 mt-1">
                      Evidence: {o.evidence_sources.join(", ")}
                    </p>
                  )}
                  {o.container_evidence?.length > 0 && (
                    <p className="text-xs text-orange-400 mt-0.5">
                      Container: {o.container_evidence.join(", ")}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </Section>
      )}

      {/* ── 4. TLS Analysis ── */}
      <Section title="TLS Analysis" icon={Lock} count={tlsResults.length} defaultOpen>
        {tlsResults.length === 0 ? <p className="text-sm text-slate-400">No TLS data.</p> :
          tlsResults.map((t: any, i: number) => (
            <div key={i} className="rounded-xl border border-slate-200 overflow-hidden">
              <div className="bg-slate-50 px-4 py-2 flex flex-wrap items-center gap-3">
                <span className="font-mono font-bold text-slate-800">{t.host}:{t.port}</span>
                {t.negotiated_cipher && (
                  <span className="text-xs bg-blue-50 text-blue-700 px-2 py-0.5 rounded font-mono">{t.negotiated_cipher}</span>
                )}
                {t.forward_secrecy && <span className="text-xs bg-green-50 text-green-700 px-2 py-0.5 rounded">PFS ✓</span>}
                {t.leaf_cert?.quantum_vulnerable && <span className="text-xs bg-red-50 text-red-700 px-2 py-0.5 rounded">Quantum Vulnerable</span>}
              </div>
              <div className="p-4 space-y-3">
                {/* TLS versions */}
                <div>
                  <p className="text-xs font-semibold text-slate-500 mb-1">TLS Versions Supported</p>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(t.tls_versions_supported || {}).map(([ver, sup]) => (
                      <span key={ver} className={`text-xs px-2 py-0.5 rounded font-mono border ${
                        sup ? "bg-green-50 text-green-700 border-green-200" : "bg-slate-50 text-slate-400 border-slate-200"
                      }`}>{ver}: {sup ? "✓" : "✗"}</span>
                    ))}
                  </div>
                </div>
                {/* Cert */}
                {t.leaf_cert && (
                  <div>
                    <p className="text-xs font-semibold text-slate-500 mb-1">Certificate</p>
                    <div className="space-y-1 bg-slate-50 rounded-lg p-3">
                      <KV label="Subject" value={t.leaf_cert.subject} />
                      <KV label="Issuer" value={t.leaf_cert.issuer} />
                      <KV label="Valid From" value={fmtDate(t.leaf_cert.valid_from)} />
                      <KV label="Valid To" value={fmtDate(t.leaf_cert.valid_to)} />
                      <KV label="Days Until Expiry" value={
                        <span className={t.leaf_cert.days_until_expiry < 30 ? "text-red-600 font-bold" : "text-green-600"}>
                          {t.leaf_cert.days_until_expiry ?? "—"}
                        </span>
                      } />
                      <KV label="Key Type / Size" value={`${t.leaf_cert.key_type} ${t.leaf_cert.key_size}-bit`} />
                      <KV label="Sig Algorithm" value={t.leaf_cert.sig_algorithm} />
                      <KV label="SANs" value={(t.leaf_cert.sans || []).join(", ")} />
                    </div>
                  </div>
                )}
                {/* Ciphers */}
                {(t.accepted_ciphers || []).length > 0 && (
                  <details>
                    <summary className="text-xs text-slate-500 cursor-pointer font-semibold">
                      Cipher Suites ({t.accepted_ciphers.length})
                    </summary>
                    <div className="mt-2 overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="border-b border-slate-100">
                            {["Cipher","Kex","Auth","Enc","Bits","PFS","Strength"].map(h => (
                              <th key={h} className="text-left py-1 pr-3 font-semibold text-slate-400 uppercase">{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {t.accepted_ciphers.map((c: any, ci: number) => (
                            <tr key={ci} className="border-b border-slate-50">
                              <td className="py-1 pr-3 font-mono text-slate-800">{c.name}</td>
                              <td className="py-1 pr-3 text-slate-600">{c.kex}</td>
                              <td className="py-1 pr-3 text-slate-600">{c.auth}</td>
                              <td className="py-1 pr-3 text-slate-600">{c.encryption}</td>
                              <td className="py-1 pr-3 text-slate-600">{c.bits}</td>
                              <td className="py-1 pr-3">{c.pfs ? "✓" : "✗"}</td>
                              <td className={`py-1 pr-3 font-semibold ${strengthColor(c.strength)}`}>{c.strength}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </details>
                )}
              </div>
            </div>
          ))
        }
      </Section>

      {/* ── 5. Crypto Findings (CBOM) ── */}
      <Section title="Crypto / CBOM Findings" icon={Shield} count={cbom.length} defaultOpen>
        {cbom.length === 0 ? <p className="text-sm text-slate-400">No findings.</p> : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-100">
                  {["Host","Component","Algorithm","Quantum Risk","HNDL","Threat Vector","Recommendation"].map(h => (
                    <th key={h} className="text-left py-1.5 pr-3 font-semibold text-slate-500 uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {cbom.map((c: any, i: number) => (
                  <tr key={i} className="border-b border-slate-50 hover:bg-slate-50">
                    <td className="py-1.5 pr-3 font-mono text-slate-700">{c.host}</td>
                    <td className="py-1.5 pr-3 text-slate-600">{c.component}</td>
                    <td className="py-1.5 pr-3 font-mono font-bold text-slate-800">{c.algorithm}</td>
                    <td className="py-1.5 pr-3">
                      <span className={`px-1.5 py-0.5 rounded border text-xs font-semibold ${riskColor(c.quantum_risk)}`}>
                        {c.quantum_risk}
                      </span>
                    </td>
                    <td className="py-1.5 pr-3">
                      {c.hndl_risk === "yes"
                        ? <AlertTriangle className="h-3.5 w-3.5 text-red-500" />
                        : <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />}
                    </td>
                    <td className="py-1.5 pr-3 text-slate-500 max-w-[200px]">{c.threat_vector}</td>
                    <td className="py-1.5 text-slate-600">{c.nist_recommendation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {/* ── 6. CDN / WAF / Cloud ── */}
      <Section title="CDN / WAF / Cloud Intelligence" icon={Wifi} count={cdnWaf.length}>
        {cdnWaf.length === 0 ? <p className="text-sm text-slate-400">No data.</p> : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {cdnWaf.map((c: any, i: number) => {
              const hasCdn = !!c.cdn_provider;
              const hasWaf = !!c.waf_detected;
              const hasCloud = !!c.cloud_provider;
              return (
                <div key={i} className="rounded-xl border border-slate-200 p-3 space-y-1.5">
                  <p className="font-mono font-bold text-slate-800 text-sm">{c.host}</p>
                  <KV label="CDN" value={
                    hasCdn
                      ? <span className="text-blue-700 font-semibold">{c.cdn_provider}</span>
                      : <span className="text-slate-400 italic">Not Detected</span>
                  } />
                  <KV label="WAF" value={
                    hasWaf
                      ? <span className="text-orange-700 font-semibold">{c.waf_provider || "Detected"}</span>
                      : <span className="text-slate-400 italic">Not Detected</span>
                  } />
                  <KV label="Proxy" value={c.reverse_proxy || <span className="text-slate-400 italic">—</span>} />
                  <KV label="Cloud" value={
                    hasCloud
                      ? <span className="text-violet-700 font-semibold">{c.cloud_provider}</span>
                      : <span className="text-slate-400 italic">—</span>
                  } />
                  {(c.cdn_evidence?.length > 0 || c.waf_evidence?.length > 0 || c.cloud_evidence?.length > 0) && (
                    <p className="text-xs text-slate-400">
                      Evidence: {[...(c.cdn_evidence || []), ...(c.waf_evidence || []), ...(c.cloud_evidence || [])].join(", ")}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Section>

      {/* ── 7. Tech Fingerprints ── */}
      {techFp.length > 0 && (
        <Section title="Technology Fingerprints" icon={Cpu} count={techFp.length}>
          <div className="flex flex-wrap gap-2">
            {techFp.map((t: any, i: number) => (
              <span key={i} className="text-xs bg-violet-50 text-violet-700 border border-violet-200 px-2 py-0.5 rounded font-mono">
                {t.host} · {t.name} {t.version || ""}
              </span>
            ))}
          </div>
        </Section>
      )}

      {/* ── 8. Web Profiles ── */}
      {webProfiles.length > 0 && (
        <Section title="Web / API Profiles" icon={Eye} count={webProfiles.length}>
          {webProfiles.map((w: any, i: number) => (
            <div key={i} className="rounded-xl border border-slate-200 p-3 space-y-2">
              <p className="font-mono font-bold text-slate-800">{w.host}</p>
              {w.header_audit && (
                <div>
                  <p className="text-xs font-semibold text-slate-500 mb-1">Security Headers</p>
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(w.header_audit).map(([k, v]) => (
                      <span key={k} className={`text-xs px-2 py-0.5 rounded border font-mono ${
                        v ? "bg-green-50 text-green-700 border-green-200" : "bg-red-50 text-red-700 border-red-200"
                      }`}>{k}: {v ? "✓" : "✗"}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </Section>
      )}

      {/* ── 9. WHOIS ── */}
      {whois && Object.keys(whois).length > 0 && (
        <Section title="WHOIS Information" icon={FileText}>
          <div className="bg-slate-50 rounded-lg p-3 space-y-1">
            <KV label="Registrar" value={whois.registrar} />
            <KV label="Created" value={fmtDate(whois.creation_date)} />
            <KV label="Expires" value={fmtDate(whois.expiration_date)} />
            <KV label="Updated" value={fmtDate(whois.updated_date)} />
            <KV label="Name Servers" value={(whois.name_servers || []).join(", ")} />
            <KV label="Country" value={whois.country} />
            <KV label="Org" value={whois.org} />
          </div>
        </Section>
      )}

      {/* ── 10. CVE / Vuln Findings ── */}
      {(vuln.length > 0 || cve.length > 0) && (
        <Section title="Vulnerability / CVE Findings" icon={AlertTriangle} count={vuln.length + cve.length}>
          {[...cve, ...vuln].map((f: any, i: number) => (
            <div key={i} className="rounded-lg border border-red-100 bg-red-50 px-3 py-2">
              <div className="flex flex-wrap items-center gap-2">
                <XCircle className="h-4 w-4 text-red-500 shrink-0" />
                <span className="font-mono font-bold text-red-800 text-sm">{f.cve_id || f.template_id || "Finding"}</span>
                {f.severity && <span className={`text-xs px-2 py-0.5 rounded border font-semibold ${riskColor(f.severity)}`}>{f.severity}</span>}
              </div>
              {f.description && <p className="text-xs text-slate-600 mt-1 ml-6">{f.description}</p>}
              {f.host && <p className="text-xs text-slate-400 mt-0.5 ml-6 font-mono">{f.host}</p>}
            </div>
          ))}
        </Section>
      )}

      {/* ── 11. Quantum Score ── */}
      {Object.keys(qs).length > 0 && (
        <Section title="Quantum Risk Score" icon={Hash} defaultOpen>
          <div className="grid sm:grid-cols-2 gap-4">
            <div className="bg-slate-50 rounded-xl p-4 space-y-2">
              <KV label="Score" value={
                <span className="text-lg font-bold">
                  {typeof qs.score === "number" ? qs.score.toFixed(1) : qs.score}
                  <span className="text-xs font-normal text-slate-400 ml-1">/ 100</span>
                </span>
              } />
              <KV label="Risk Level" value={
                qs.risk_level
                  ? <span className={`px-2 py-0.5 rounded border text-xs font-semibold ${riskColor(qs.risk_level)}`}>{qs.risk_level}</span>
                  : "—"
              } />
              <KV label="Confidence" value={
                typeof qs.confidence === "number"
                  ? `${(qs.confidence * 100).toFixed(0)}%`
                  : qs.confidence ?? "—"
              } />
              <KV label="Aggregation" value={qs.aggregation ?? "—"} />
              <KV label="Catalog Version" value={qs.catalog_version ?? "—"} />
              <KV label="PQC Ready" value={
                qs.score >= 80
                  ? <span className="text-green-600 font-bold">✓ Yes</span>
                  : <span className="text-red-500 font-bold">✗ No</span>
              } />
            </div>
            {/* Breakdown per category */}
            {qs.breakdown && (
              <div className="space-y-3">
                <p className="text-xs font-semibold text-slate-500 uppercase">Category Breakdown</p>
                {[
                  { key: "key_exchange_score", label: "Key Exchange", weight: "36%" },
                  { key: "signature_score", label: "Signature", weight: "28%" },
                  { key: "cipher_score", label: "Cipher", weight: "18%" },
                  { key: "hash_score", label: "Hash", weight: "10%" },
                  { key: "protocol_score", label: "Protocol", weight: "8%" },
                ].map(({ key, label, weight }) => {
                  const val = qs.breakdown[key];
                  const pct = typeof val === "number" ? val : 0;
                  return (
                    <div key={key}>
                      <div className="flex justify-between text-xs mb-0.5">
                        <span className="text-slate-600 font-medium">{label} <span className="text-slate-400">({weight})</span></span>
                        <span className="font-mono font-bold text-slate-800">{pct.toFixed(0)}/100</span>
                      </div>
                      <div className="w-full bg-slate-200 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full transition-all ${
                            pct >= 80 ? "bg-green-500" : pct >= 60 ? "bg-blue-500" : pct >= 40 ? "bg-yellow-500" : pct >= 20 ? "bg-orange-500" : "bg-red-500"
                          }`}
                          style={{ width: `${Math.min(100, pct)}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
          {/* Summary */}
          {qs.summary && (
            <div className="mt-3 bg-blue-50 border border-blue-100 rounded-lg p-3 text-sm text-blue-800">
              {qs.summary}
            </div>
          )}
          {/* Drivers */}
          {qs.drivers && qs.drivers.length > 0 && (
            <div className="mt-3 space-y-1.5">
              <p className="text-xs font-semibold text-slate-500 uppercase">Top Risk Drivers</p>
              {qs.drivers.map((d: string, i: number) => (
                <div key={i} className="flex gap-2 text-sm text-slate-700">
                  <span className="text-red-500 font-bold shrink-0">⚠</span>
                  <span className="font-mono text-xs">{d}</span>
                </div>
              ))}
            </div>
          )}
        </Section>
      )}
    </div>
  );
}
