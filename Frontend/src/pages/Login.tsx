import { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth, UserRole } from "@/contexts/AuthContext";
import { Shield, Eye, EyeOff, ArrowLeft, Mail, Clock } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { z } from "zod";
import { authService } from "@/services/api";

const loginSchema = z.object({
  username: z.string().min(1, "Username is required").max(255),
  password: z.string().min(1, "Password is required").max(128),
});

export default function Login() {
  const [step, setStep] = useState<"login" | "otp">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [otpEmail, setOtpEmail] = useState("");
  const [otpValues, setOtpValues] = useState<string[]>(Array(6).fill(""));
  const otpRefs = useRef<(HTMLInputElement | null)[]>([]);

  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [timeLeft, setTimeLeft] = useState(60);
  
  const { login } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (step === "otp" && timeLeft > 0) {
      timer = setTimeout(() => setTimeLeft(timeLeft - 1), 1000);
    }
    return () => clearTimeout(timer);
  }, [step, timeLeft]);

  const handleResendOtp = async () => {
    try {
      await authService.resendOtp(otpEmail);
      setTimeLeft(60);
      setOtpValues(Array(6).fill(""));
      toast.success("New OTP sent to your email!");
      otpRefs.current[0]?.focus();
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Failed to resend OTP");
    }
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const result = loginSchema.safeParse({ username, password });
    if (!result.success) {
      toast.error(result.error.errors[0].message);
      return;
    }

    setLoading(true);
    try {
      const loginRes = await authService.login(username, password);
      
      if (loginRes.data.requires_otp) {
        setOtpEmail(loginRes.data.email);
        setStep("otp");
        setTimeLeft(60);
        toast.success(loginRes.data.message);
        return;
      }

      const { access_token, user } = loginRes.data;
      sessionStorage.setItem("auth_token", access_token);
      
      const backendRole = String(user?.role || "").toLowerCase();
      const mappedRole: UserRole = backendRole.includes("admin") ? "Admin" : "Employee";
      login({
          id: user?.id || "demo-id",
          username: username,
          role: mappedRole,
          name: user?.full_name || username.split("@")[0],
          email: user?.email || (username.includes("@") ? username : undefined),
        }, access_token);
      
      toast.success("Login successful");
      navigate("/");
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Authentication failed. Check your credentials.");
    } finally {
      setLoading(false);
    }
  };

  const handleOtpSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const code = otpValues.join("");
    if (code.length < 6) {
      toast.error("Please enter the full 6-digit code");
      return;
    }

    setLoading(true);
    try {
      const res = await authService.verifyOtp(otpEmail, code);
      const { access_token, user } = res.data;
      sessionStorage.setItem("auth_token", access_token);
      
      const backendRole = String(user?.role || "").toLowerCase();
      const mappedRole: UserRole = backendRole.includes("admin") ? "Admin" : "Employee";
      login({
          id: user?.id || "demo-id",
          username: username,
          role: mappedRole,
          name: user?.full_name || username.split("@")[0],
          email: user?.email || (username.includes("@") ? username : undefined),
        }, access_token);
      
      toast.success("Authentication successful");
      navigate("/");
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Invalid or expired OTP");
    } finally {
      setLoading(false);
    }
  };

  const handleOtpChange = (index: number, value: string) => {
    if (!/^[0-9]?$/.test(value)) return;
    const newOtp = [...otpValues];
    newOtp[index] = value;
    setOtpValues(newOtp);
    if (value && index < 5) {
      otpRefs.current[index + 1]?.focus();
    }
  };

  const handleOtpKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && !otpValues[index] && index > 0) {
      otpRefs.current[index - 1]?.focus();
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background bg-grid-pattern relative overflow-hidden">
      <div className="absolute top-1/4 -left-32 w-64 h-64 rounded-full bg-primary/5 blur-3xl" />
      <div className="absolute bottom-1/4 -right-32 w-64 h-64 rounded-full bg-accent/5 blur-3xl" />

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.4 }}
        className="w-full max-w-md mx-4"
      >
        <div className="rounded-2xl border border-border bg-card p-8 shadow-2xl relative">
          
          {step === "otp" && (
            <button 
              onClick={() => { setStep("login"); setOtpValues(Array(6).fill("")); }}
              className="absolute top-6 left-6 text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeft className="h-5 w-5" />
            </button>
          )}

          <div className="text-center mb-8 mt-2">
            <div className="inline-flex h-14 w-14 items-center justify-center rounded-xl bg-primary mb-4">
              {step === "login" ? (
                <Shield className="h-7 w-7 text-primary-foreground" />
              ) : (
                <Mail className="h-7 w-7 text-primary-foreground" />
              )}
            </div>
            <h1 className="text-xl font-bold text-foreground">
              {step === "login" ? "QSCAS" : "Two-Step Verification"}
            </h1>
            <p className="text-xs text-muted-foreground mt-2">
              {step === "login" 
                ? "PSB Hackathon Series — In collaboration with IIT Kanpur"
                : `We sent a 6-digit code to ${otpEmail}`
              }
            </p>
          </div>

          {step === "login" ? (
            <form onSubmit={handleLoginSubmit} className="space-y-5">
              <div className="space-y-2">
                <Label htmlFor="username" className="text-xs text-muted-foreground uppercase tracking-wider">
                  Email
                </Label>
                <Input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter Email Address"
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

              <div className="flex justify-end pt-2">
                <button
                  type="button"
                  className="text-xs text-primary hover:text-primary/80 transition-colors"
                  onClick={async () => {
                    if (!username.trim()) { toast.error("Enter your username first"); return; }
                    try {
                      await authService.forgotPassword(username.trim());
                      toast.success("If the account exists, a reset link has been sent.");
                    } catch { toast.success("If the account exists, a reset link has been sent."); }
                  }}
                >
                  Forgot Password?
                </button>
              </div>

              <Button type="submit" disabled={loading} className="w-full h-10 bg-primary text-primary-foreground font-semibold hover:bg-primary/90 transition-all">
                {loading ? "Authenticating..." : "Sign In"}
              </Button>

             
            </form>
          ) : (
            <div className="space-y-6">
              <form onSubmit={handleOtpSubmit} className="space-y-6">
                <div className="flex justify-between gap-2 px-2">
                  {otpValues.map((v, i) => (
                    <Input
                      key={i}
                      ref={(el) => (otpRefs.current[i] = el)}
                      type="text"
                      inputMode="numeric"
                      maxLength={1}
                      value={v}
                      disabled={timeLeft === 0}
                      onChange={(e) => handleOtpChange(i, e.target.value)}
                      onKeyDown={(e) => handleOtpKeyDown(i, e)}
                      className={`w-12 h-14 text-center text-xl font-bold bg-secondary border-border focus:border-primary focus:ring-1 focus:ring-primary shadow-sm ${timeLeft === 0 ? "opacity-50 cursor-not-allowed" : ""}`}
                    />
                  ))}
                </div>
                
                <div className="flex flex-col items-center justify-center space-y-2 mt-4">
                  <div className="flex items-center text-xs text-muted-foreground font-medium">
                    <Clock className="w-3.5 h-3.5 mr-1" />
                    {timeLeft > 0 ? (
                      <span className={timeLeft <= 10 ? "text-red-500" : ""}>
                        Code expires in 00:{timeLeft < 10 ? `0${timeLeft}` : timeLeft}
                      </span>
                    ) : (
                      <span className="text-red-500">Code expired</span>
                    )}
                  </div>
                </div>
                
                <Button 
                  type="submit" 
                  disabled={loading || otpValues.join("").length < 6 || timeLeft === 0} 
                  className="w-full h-10 bg-primary text-primary-foreground font-semibold hover:bg-primary/90 transition-all mt-2"
                >
                  {loading ? "Verifying..." : "Verify Code"}
                </Button>
              </form>

              <div className="text-center">
                <button
                  type="button"
                  onClick={handleResendOtp}
                  disabled={timeLeft > 0}
                  className={`text-xs font-semibold transition-colors ${
                    timeLeft > 0 
                      ? "text-muted-foreground cursor-not-allowed opacity-50" 
                      : "text-primary hover:text-primary/80"
                  }`}
                >
                  Didn't receive a code? Resend
                </button>
              </div>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
