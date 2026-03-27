import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes, Navigate } from "react-router-dom";
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
import Reporting from "./pages/Reporting";
import Admin from "./pages/Admin";
import Migration from "./pages/Migration";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <DashboardLayout>{children}</DashboardLayout>;
}

function RoleRoute({
  children,
  allowedRoles,
}: {
  children: React.ReactNode;
  allowedRoles: string[];
}) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  if (!allowedRoles.includes(user.role)) return <Navigate to="/" replace />;
  return <>{children}</>;
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
      <Route path="/asset-inventory" element={<ProtectedRoute><AssetInventory /></ProtectedRoute>} />
      <Route path="/asset-discovery" element={<ProtectedRoute><AssetDiscovery /></ProtectedRoute>} />
      <Route path="/cbom" element={<ProtectedRoute><CBOM /></ProtectedRoute>} />
      <Route path="/pqc-posture" element={<ProtectedRoute><PQCPosture /></ProtectedRoute>} />
      <Route path="/cyber-rating" element={<ProtectedRoute><CyberRating /></ProtectedRoute>} />
      <Route
        path="/reporting"
        element={
          <ProtectedRoute>
            {/* <RoleRoute allowedRoles={["admin"]}> */}
              <Reporting />
            {/* </RoleRoute> */}
          </ProtectedRoute>
        }
      />
      <Route path="/admin" element={<ProtectedRoute><Admin /></ProtectedRoute>} />
      <Route path="/migration" element={<ProtectedRoute><Migration /></ProtectedRoute>} />
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
