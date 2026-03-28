import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
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
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <DashboardLayout>{children}</DashboardLayout>;
}

function AppRoutes() {
  const { isAuthenticated } = useAuth();

  return (
    <Routes>
      <Route
        path="/login"
        element={isAuthenticated ? <Navigate to="/" replace /> : <Login />}
      />
      <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
      <Route path="/inventory" element={<ProtectedRoute><AssetInventory /></ProtectedRoute>} />
      <Route path="/asset-inventory" element={<Navigate to="/inventory" replace />} />
      <Route path="/inventory-runs" element={<ProtectedRoute><InventoryRuns /></ProtectedRoute>} />
      <Route path="/crypto-findings" element={<ProtectedRoute><CryptoFindings /></ProtectedRoute>} />
      <Route path="/policy" element={<ProtectedRoute><PolicyStandards /></ProtectedRoute>} />
      <Route path="/asset-discovery" element={<ProtectedRoute><AssetDiscovery /></ProtectedRoute>} />
      <Route path="/cbom" element={<ProtectedRoute><CBOM /></ProtectedRoute>} />
      <Route path="/pqc-posture" element={<ProtectedRoute><PQCPosture /></ProtectedRoute>} />
      <Route path="/cyber-rating" element={<ProtectedRoute><CyberRating /></ProtectedRoute>} />
      <Route path="/reporting" element={<Navigate to="/admin" replace />} />
      <Route path="/admin" element={<ProtectedRoute><Admin /></ProtectedRoute>} />
      <Route path="/migration" element={<ProtectedRoute><Migration /></ProtectedRoute>} />
      <Route path="/executive-brief" element={<ProtectedRoute><ExecutiveBrief /></ProtectedRoute>} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

const App = () => (
  <QueryClientProvider client={queryClient}>
    <AuthProvider>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
      </TooltipProvider>
    </AuthProvider>
  </QueryClientProvider>
);

export default App;
