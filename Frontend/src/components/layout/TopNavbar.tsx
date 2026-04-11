import { Bell, HelpCircle, LogOut, Mail, Search, Settings, User } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { useNavigate } from "react-router-dom";
import { useCallback, useEffect, useState } from "react";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ApiHealthIndicator } from "@/components/common/ApiHealthIndicator";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ContactAdminSheet } from "@/components/notifications/ContactAdminSheet";
import { adminService } from "@/services/api";

export function TopNavbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [contactOpen, setContactOpen] = useState(false);
  const [unreadAdmin, setUnreadAdmin] = useState(0);

  const isAdmin = user?.role === "Admin";
  const isEmployee = user?.role === "Employee";

  const refreshUnread = useCallback(async () => {
    if (!isAdmin) {
      setUnreadAdmin(0);
      return;
    }
    try {
      const res = await adminService.listNotifications({ limit: 1, skip: 0, unread_only: true });
      const total = typeof res.data?.total === "number" ? res.data.total : 0;
      setUnreadAdmin(total);
    } catch {
      setUnreadAdmin(0);
    }
  }, [isAdmin]);

  useEffect(() => {
    void refreshUnread();
    const t = window.setInterval(() => void refreshUnread(), 60_000);
    const onFocus = () => void refreshUnread();
    window.addEventListener("focus", onFocus);
    const onInbox = () => void refreshUnread();
    window.addEventListener("qs-notifications-updated", onInbox);
    return () => {
      window.clearInterval(t);
      window.removeEventListener("focus", onFocus);
      window.removeEventListener("qs-notifications-updated", onInbox);
    };
  }, [refreshUnread]);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const displayName = user?.username
    ? user.username.split("@")[0].substring(0, 24)
    : user?.name || "Analyst";

  return (
    <>
      <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-4 border-b border-slate-200/90 bg-white/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-white/80 md:px-6">
        <div className="flex min-w-0 flex-1 items-center gap-3">
          <SidebarTrigger className="text-slate-600 hover:bg-slate-100 hover:text-slate-900" />
          <span className="hidden font-semibold tracking-tight text-slate-900 sm:inline">QuantumShield</span>
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

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="relative text-slate-500 hover:text-slate-900"
                aria-label={isAdmin ? "Notifications" : "Messages"}
              >
                <Bell className="h-4 w-4" />
                {isAdmin && unreadAdmin > 0 ? (
                  <span className="absolute right-1.5 top-1.5 flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-red-500 px-0.5 text-[9px] font-bold text-white ring-2 ring-white">
                    {unreadAdmin > 99 ? "99+" : unreadAdmin}
                  </span>
                ) : null}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              {isEmployee && (
                <>
                  <DropdownMenuItem
                    className="gap-2 cursor-pointer"
                    onClick={() => {
                      setContactOpen(true);
                    }}
                  >
                    <Mail className="h-4 w-4" />
                    Contact administrators
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                </>
              )}
              {isAdmin && (
                <>
                  <DropdownMenuItem
                    className="gap-2 cursor-pointer"
                    onClick={() => navigate("/admin?tab=inbox")}
                  >
                    <Bell className="h-4 w-4" />
                    Open inbox
                    {unreadAdmin > 0 ? (
                      <span className="ml-auto text-xs text-muted-foreground">{unreadAdmin} unread</span>
                    ) : null}
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                </>
              )}
              {!isEmployee && !isAdmin && (
                <DropdownMenuItem disabled className="text-xs text-muted-foreground">
                  Sign in as employee or admin to use messages.
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>

          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="text-slate-500 hover:text-slate-900"
            aria-label="About"
            onClick={() => navigate("/about")}
          >
            <HelpCircle className="h-4 w-4" />
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="text-slate-500 hover:text-slate-900"
            aria-label="Settings"
            onClick={() => navigate("/settings")}
          >
            <Settings className="h-4 w-4" />
          </Button>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className="ml-1 flex items-center gap-2 rounded-full pl-2 pr-1 text-slate-700 hover:bg-slate-100"
              >
                <span className="hidden max-w-[120px] truncate text-xs font-medium sm:inline">{displayName}</span>
                <span className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-200 text-slate-600">
                  <User className="h-4 w-4" />
                </span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              {isEmployee && (
                <DropdownMenuItem
                  className="gap-2 cursor-pointer"
                  onClick={() => {
                    setContactOpen(true);
                  }}
                >
                  <Mail className="h-4 w-4" />
                  Contact administrators
                </DropdownMenuItem>
              )}
              {isEmployee && <DropdownMenuSeparator />}
              <DropdownMenuItem onClick={handleLogout} className="gap-2">
                <LogOut className="h-4 w-4" />
                Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>

      {isEmployee && <ContactAdminSheet open={contactOpen} onOpenChange={setContactOpen} />}
    </>
  );
}
