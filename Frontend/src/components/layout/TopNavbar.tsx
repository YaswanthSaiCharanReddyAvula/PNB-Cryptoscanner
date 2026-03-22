import { Bell, LogOut, User } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { useNavigate } from "react-router-dom";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";

// PQC-Ready Shield Badge — SVG inline
function PQCShieldBadge() {
  return (
    <svg
      width="44"
      height="50"
      viewBox="0 0 44 50"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="drop-shadow-md"
    >
      {/* Shield body */}
      <path
        d="M22 2L4 9.5V23C4 33.5 12 42.8 22 47C32 42.8 40 33.5 40 23V9.5L22 2Z"
        fill="#A20E37"
        stroke="#FBBC09"
        strokeWidth="2"
      />
      {/* Gold accent band */}
      <path
        d="M22 2L4 9.5V14L22 7L40 14V9.5L22 2Z"
        fill="#FBBC09"
        opacity="0.9"
      />
      {/* PNB text */}
      <text
        x="22"
        y="27"
        textAnchor="middle"
        fill="#FBBC09"
        fontSize="8"
        fontWeight="bold"
        fontFamily="monospace"
        letterSpacing="1"
      >
        PNB
      </text>
      {/* PQC-Ready text */}
      <text
        x="22"
        y="37"
        textAnchor="middle"
        fill="white"
        fontSize="5"
        fontWeight="600"
        fontFamily="sans-serif"
        letterSpacing="0.5"
      >
        PQC-READY
      </text>
    </svg>
  );
}

export function TopNavbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const displayName = user?.username
    ? user.username.split("@")[0].substring(0, 18)
    : user?.name || "User";

  return (
    <header className="h-14 border-b border-border bg-card/80 backdrop-blur-sm flex items-center justify-between px-4 sticky top-0 z-30">
      {/* Left: Sidebar trigger + system name */}
      <div className="flex items-center gap-2 min-w-0">
        <SidebarTrigger className="text-muted-foreground hover:text-foreground flex-shrink-0" />
        <span className="text-sm font-medium text-muted-foreground hidden sm:block truncate">
          Quantum-Safe Cryptography Assessment System
        </span>
      </div>

      {/* Center: PQC Shield Badge */}
      <div className="absolute left-1/2 -translate-x-1/2 flex items-center">
        <PQCShieldBadge />
      </div>

      {/* Right: Welcome text + notifications + logout */}
      <div className="flex items-center gap-2 flex-shrink-0">
        {/* Welcome */}
        <div className="hidden md:flex items-center gap-1.5 px-3 py-1 rounded-full border border-[#FBBC09]/30 bg-[#FBBC09]/5">
          <User className="h-3 w-3 text-[#FBBC09]" />
          <span className="text-xs font-medium text-[#FBBC09] max-w-[140px] truncate">
            Welcome, {displayName}..!
          </span>
        </div>

        {/* Notifications */}
        <Button variant="ghost" size="icon" className="relative text-muted-foreground hover:text-foreground">
          <Bell className="h-4 w-4" />
          <span className="absolute -top-0.5 -right-0.5 h-4 w-4 rounded-full bg-accent text-[10px] font-bold flex items-center justify-center text-accent-foreground">
            3
          </span>
        </Button>

        {/* Logout */}
        <Button
          variant="ghost"
          size="icon"
          onClick={handleLogout}
          className="text-muted-foreground hover:text-foreground"
          title="Logout"
        >
          <LogOut className="h-4 w-4" />
        </Button>
      </div>
    </header>
  );
}
