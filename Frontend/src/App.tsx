import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, HashRouter, Navigate, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import { DomainProvider } from "@/contexts/DomainContext";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import AssetInventory from "./pages/AssetInventory";
import AssetDiscovery from "./pages/AssetDiscovery";
import CBOM from "./pages/CBOM";
import PQCPosture from "./pages/PQCPosture";
import CyberRating from "./pages/CyberRating";
import Admin from "./pages/Admin";
import Migration from "./pages/Migration";
import ExecutiveBrief from "./pages/ExecutiveBrief";
import InventoryRuns from "./pages/InventoryRuns";
import CryptoFindings from "./pages/CryptoFindings";
import PolicyStandards from "./pages/PolicyStandards";
import SecurityRoadmap from "./pages/SecurityRoadmap";
import NotFound from "./pages/NotFound";
import Settings from "./pages/Settings";
import About from "./pages/About";
import Downloads from "./pages/Downloads";
import ScanResults from "./pages/ScanResults";
import NewScan from "./pages/NewScan";

const queryClient = new QueryClient();

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <DashboardLayout>{children}</DashboardLayout>;
}

function AppRoutes() {
  const { isAuthenticated } = useAuth();
  const hasElectronUA =
    typeof navigator !== "undefined" &&
    String(navigator.userAgent || "").toLowerCase().includes("electron");
  const isElectron =
    hasElectronUA ||
    (typeof window !== "undefined" &&
      !!(window as Window & { electronAPI?: { platform?: string } }).electronAPI);

  return (
    <Routes>
      <Route
        path="/login"
        element={isAuthenticated ? <Navigate to="/" replace /> : <Login />}
      />
      <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
      <Route path="/scan" element={<ProtectedRoute><NewScan /></ProtectedRoute>} />
      <Route path="/inventory" element={<ProtectedRoute><AssetInventory /></ProtectedRoute>} />
      <Route path="/asset-inventory" element={<Navigate to="/inventory" replace />} />
      <Route path="/inventory-runs" element={<ProtectedRoute><InventoryRuns /></ProtectedRoute>} />
      <Route path="/crypto-findings" element={<ProtectedRoute><CryptoFindings /></ProtectedRoute>} />
      <Route path="/policy" element={<ProtectedRoute><PolicyStandards /></ProtectedRoute>} />
      <Route path="/asset-discovery" element={<ProtectedRoute><AssetDiscovery /></ProtectedRoute>} />
      <Route path="/cbom" element={<ProtectedRoute><CBOM /></ProtectedRoute>} />
      <Route path="/pqc-posture" element={<ProtectedRoute><PQCPosture /></ProtectedRoute>} />
      <Route path="/cyber-rating" element={<ProtectedRoute><CyberRating /></ProtectedRoute>} />
      <Route path="/security-roadmap" element={<ProtectedRoute><SecurityRoadmap /></ProtectedRoute>} />
      <Route path="/copilot" element={<Navigate to="/" replace />} />
      <Route path="/reporting" element={<Navigate to="/admin" replace />} />
      <Route path="/admin" element={<ProtectedRoute><Admin /></ProtectedRoute>} />
      <Route path="/migration" element={<ProtectedRoute><Migration /></ProtectedRoute>} />
      <Route path="/executive-brief" element={<ProtectedRoute><ExecutiveBrief /></ProtectedRoute>} />
      {!isElectron && (
        <Route path="/downloads" element={<ProtectedRoute><Downloads /></ProtectedRoute>} />
      )}
      <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
      <Route path="/about" element={<ProtectedRoute><About /></ProtectedRoute>} />
      <Route path="/scan-results/:domain" element={<ProtectedRoute><ScanResults /></ProtectedRoute>} />
      <Route path="/scan-results" element={<ProtectedRoute><ScanResults /></ProtectedRoute>} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

/** Hash routes in Electron (file:// or dev server) so navigation works; browser keeps history API. */
function AppRouterShell({ children }: { children: React.ReactNode }) {
  const hasElectronUA =
    typeof navigator !== "undefined" &&
    String(navigator.userAgent || "").toLowerCase().includes("electron");
  const isElectron =
    hasElectronUA ||
    (typeof window !== "undefined" &&
      !!(window as Window & { electronAPI?: { platform?: string } }).electronAPI);
  const Router = isElectron ? HashRouter : BrowserRouter;
  return <Router>{children}</Router>;
}

const App = () => (
  <QueryClientProvider client={queryClient}>
    <AuthProvider>
      <DomainProvider>
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <AppRouterShell>
            <AppRoutes />
          </AppRouterShell>
        </TooltipProvider>
      </DomainProvider>
    </AuthProvider>
  </QueryClientProvider>
);

export default App;
