import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth, UserRole } from "@/contexts/AuthContext";
import { Shield, Eye, EyeOff } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { z } from "zod";
import { authService, userService } from "@/services/api";

const loginSchema = z.object({
  username: z.string().min(1, "Username is required").max(255),
  password: z.string().min(1, "Password is required").max(128),
});

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("Admin");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const result = loginSchema.safeParse({ username, password });
    if (!result.success) {
      toast.error(result.error.errors[0].message);
      return;
    }

    setLoading(true);
    try {
      // 1. Authenticate with backend
      const loginRes = await authService.login(username, password);
      const { access_token, user } = loginRes.data;

      // 2. Set token so the interceptor adds it for the next call
      sessionStorage.setItem("auth_token", access_token);

      // 3. Log in to Context using the returned mocked user object or local state
      login(
        { 
          id: user?.id || "demo-id", 
          username: username, 
          role: role, 
          name: user?.full_name || username.split("@")[0]
        },
        access_token
      );
      
      toast.success("Login successful");
      navigate("/");
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Authentication failed. Check your credentials.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background bg-grid-pattern relative overflow-hidden">
      {/* Background decorations */}
      <div className="absolute top-1/4 -left-32 w-64 h-64 rounded-full bg-primary/5 blur-3xl" />
      <div className="absolute bottom-1/4 -right-32 w-64 h-64 rounded-full bg-accent/5 blur-3xl" />

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.4 }}
        className="w-full max-w-md mx-4"
      >
        <div className="rounded-2xl border border-border bg-card p-8 shadow-2xl">
          {/* Partner Logos Strip */}
          <div className="flex items-center justify-around gap-2 pb-5 mb-5 border-b border-border/60">
            {[
              { code: "DFS", label: "Dept. of Financial Services", bg: "#1a237e" },
              { code: "IITK", label: "IIT Kanpur", bg: "#7b1111" },
              { code: "PNB", label: "Punjab National Bank", bg: "#A20E37" },
              { code: "GMRIT", label: "GMR Institute", bg: "#1b5e20" },
            ].map((logo) => (
              <div key={logo.code} className="flex flex-col items-center gap-1">
                <div
                  className="h-10 w-10 rounded-lg flex items-center justify-center text-white font-bold text-[10px] text-center leading-tight"
                  style={{ backgroundColor: logo.bg }}
                >
                  {logo.code}
                </div>
                <span className="text-[8px] text-muted-foreground text-center max-w-[52px] leading-tight hidden sm:block">{logo.label}</span>
              </div>
            ))}
          </div>

          {/* Logo */}
          <div className="text-center mb-8">
            <div className="inline-flex h-14 w-14 items-center justify-center rounded-xl bg-primary mb-4">
              <Shield className="h-7 w-7 text-primary-foreground" />
            </div>
            <h1 className="text-xl font-bold text-foreground">QSCAS</h1>
            <p className="text-xs text-muted-foreground mt-1">
              PSB Hackathon Series — In collaboration with IIT Kanpur
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="username" className="text-xs text-muted-foreground uppercase tracking-wider">
                Username
              </Label>
              <Input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username or email (e.g. admin)"
                className="bg-secondary border-border h-10"
                autoComplete="username"
                maxLength={100}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password" className="text-xs text-muted-foreground uppercase tracking-wider">
                Password
              </Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password"
                  className="bg-secondary border-border h-10 pr-10"
                  autoComplete="current-password"
                  maxLength={128}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="role" className="text-xs text-muted-foreground uppercase tracking-wider">
                Role
              </Label>
              <select
                id="role"
                value={role}
                onChange={(e) => setRole(e.target.value as UserRole)}
                className="flex h-10 w-full rounded-md border border-input bg-secondary px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 border-border"
              >
                <option value="Admin">Admin</option>
                <option value="Employee">Employee</option>
              </select>
            </div>

            <div className="flex justify-end">
              <button
                type="button"
                className="text-xs text-primary hover:text-primary/80 transition-colors"
                onClick={async () => {
                  if (!username.trim()) {
                    toast.error("Enter your username first");
                    return;
                  }
                  try {
                    await authService.forgotPassword(username.trim());
                    toast.success("If the account exists, a reset link has been sent.");
                  } catch {
                    toast.success("If the account exists, a reset link has been sent.");
                  }
                }}
              >
                Forgot Password?
              </button>
            </div>

            <Button
              type="submit"
              disabled={loading}
              className="w-full h-10 bg-primary text-primary-foreground font-semibold hover:bg-primary/90 transition-all"
            >
              {loading ? "Authenticating..." : "Sign In"}
            </Button>

            <p className="text-center text-[10px] text-muted-foreground mt-4">
              Demo: admin@quantumshield.com / admin123
            </p>
          </form>
        </div>
      </motion.div>
    </div>
  );
}
