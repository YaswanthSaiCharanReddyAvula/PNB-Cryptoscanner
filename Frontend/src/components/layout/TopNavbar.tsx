import { Bell, HelpCircle, LogOut, Search, Settings, User } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { useNavigate } from "react-router-dom";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ApiHealthIndicator } from "@/components/common/ApiHealthIndicator";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export function TopNavbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const displayName = user?.username
    ? user.username.split("@")[0].substring(0, 24)
    : user?.name || "Analyst";

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-4 border-b border-slate-200/90 bg-white/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-white/80 md:px-6">
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <SidebarTrigger className="text-slate-600 hover:bg-slate-100 hover:text-slate-900" />
        <span className="hidden font-semibold tracking-tight text-slate-900 sm:inline">
          QuantumShield
        </span>
      </div>

      <div className="hidden max-w-md flex-1 md:block">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <Input
            placeholder="Search…"
            className="h-9 border-slate-200 bg-slate-50 pl-9 text-sm text-slate-800 placeholder:text-slate-400"
            readOnly
            onFocus={(e) => e.target.blur()}
          />
        </div>
      </div>

      <div className="flex flex-shrink-0 items-center gap-1">
        <ApiHealthIndicator />
        <Button variant="ghost" size="icon" className="relative text-slate-500 hover:text-slate-900">
          <Bell className="h-4 w-4" />
          <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-red-500 ring-2 ring-white" />
        </Button>
        <Button variant="ghost" size="icon" className="text-slate-500 hover:text-slate-900">
          <HelpCircle className="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="icon" className="text-slate-500 hover:text-slate-900">
          <Settings className="h-4 w-4" />
        </Button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              className="ml-1 flex items-center gap-2 rounded-full pl-2 pr-1 text-slate-700 hover:bg-slate-100"
            >
              <span className="hidden max-w-[120px] truncate text-xs font-medium sm:inline">
                {displayName}
              </span>
              <span className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-200 text-slate-600">
                <User className="h-4 w-4" />
              </span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            <DropdownMenuItem onClick={handleLogout} className="gap-2">
              <LogOut className="h-4 w-4" />
              Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
