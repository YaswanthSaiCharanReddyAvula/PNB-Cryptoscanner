import {
  LayoutDashboard,
  History,
  Boxes,
  ShieldCheck,
  AlertCircle,
  Map,
  Route,
  ScrollText,
  Settings,
  LifeBuoy,
  BookOpen,
  Zap,
  Lock,
  Star,
  FileText,
  Milestone,
} from "lucide-react";
import { NavLink } from "@/components/NavLink";
import { useLocation, Link } from "react-router-dom";
import { cn } from "@/lib/utils";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarHeader,
  SidebarFooter,
  useSidebar,
} from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";

const navItems = [
  { title: "Overview", url: "/", icon: LayoutDashboard },
  { title: "Inventory Runs", url: "/inventory-runs", icon: History },
  { title: "Inventory Assets", url: "/inventory", icon: Boxes },
  { title: "CBOM", url: "/cbom", icon: ShieldCheck },
  { title: "Crypto Findings", url: "/crypto-findings", icon: AlertCircle },
  { title: "PQC Posture", url: "/pqc-posture", icon: Lock },
  { title: "Cyber Rating", url: "/cyber-rating", icon: Star },
  { title: "Security roadmap", url: "/security-roadmap", icon: Milestone },
  { title: "Executive brief", url: "/executive-brief", icon: FileText },
  { title: "Threat Map", url: "/asset-discovery", icon: Map },
  { title: "Migration", url: "/migration", icon: Route },
  { title: "Policy & Standards", url: "/policy", icon: ScrollText },
  { title: "Admin & Reporting", url: "/admin", icon: Settings },
];

export function AppSidebar() {
  const { state, isMobile } = useSidebar();
  /** Collapsed = narrow icon rail (labels hidden); mobile sheet is always full width. */
  const collapsed = !isMobile && state === "collapsed";
  const location = useLocation();

  const isActive = (path: string) =>
    path === "/" ? location.pathname === "/" : location.pathname.startsWith(path);

  const navIconClass =
    "shrink-0 text-current transition-[color,transform] duration-150 group-hover/menu-item:scale-[1.03]";

  return (
    <Sidebar
      collapsible="icon"
      className="border-r border-sidebar-border bg-sidebar text-sidebar-foreground"
    >
      <SidebarHeader
        className={cn(
          "border-b border-sidebar-border px-4 py-4",
          collapsed && "flex justify-center px-2 py-3",
        )}
      >
        <Link
          to="/"
          title="QuantumShield"
          className={cn(
            "flex items-center gap-3 rounded-lg outline-none ring-sidebar-ring transition-opacity hover:opacity-95 focus-visible:ring-2",
            collapsed && "justify-center",
          )}
        >
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-sidebar-border/90 bg-sidebar-primary text-sidebar-primary-foreground shadow-sm">
            <ShieldCheck className="h-5 w-5 stroke-[2]" />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <p className="text-sm font-semibold text-sidebar-foreground leading-tight">
                QuantumShield
              </p>
              <p className="text-[11px] text-sidebar-foreground/65 leading-tight">
                Quantum‑safe migration platform
              </p>
            </div>
          )}
        </Link>
      </SidebarHeader>

      <SidebarContent className={cn("px-2 py-4", collapsed && "px-1")}>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu className="gap-0.5">
              {navItems.map((item) => {
                const active = isActive(item.url);
                return (
                  <SidebarMenuItem key={item.title}>
                    <SidebarMenuButton
                      asChild
                      isActive={active}
                      tooltip={item.title}
                      className="[&>svg]:!size-5 [&>svg]:!stroke-2"
                    >
                      <NavLink
                        to={item.url}
                        end={item.url === "/"}
                        className={cn(
                          "group/menu-item flex items-center gap-3 rounded-lg text-[13px] font-medium transition-colors duration-150",
                          collapsed
                            ? "justify-center px-0 py-2.5"
                            : "px-3 py-2.5",
                          active
                            ? "bg-sidebar-accent text-sidebar-accent-foreground shadow-[inset_0_0_0_1px_hsl(var(--sidebar-ring)/0.35)]"
                            : "text-sidebar-foreground/88 hover:bg-white/12 hover:text-sidebar-accent-foreground active:bg-white/16",
                        )}
                        activeClassName=""
                      >
                        <item.icon className={navIconClass} />
                        {!collapsed && <span>{item.title}</span>}
                      </NavLink>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter
        className={cn("border-t border-sidebar-border p-3", collapsed && "flex flex-col items-center gap-2 px-1 py-3")}
      >
        {!collapsed ? (
          <>
            <Button
              asChild
              className="mb-3 w-full rounded-lg bg-sidebar-primary text-sidebar-primary-foreground hover:bg-sidebar-primary/90"
            >
              <Link to="/" className="gap-2 font-semibold">
                <Zap className="h-4 w-4 stroke-[2]" />
                New scan
              </Link>
            </Button>
            <div className="flex flex-col gap-1">
              <a
                href="#"
                className="flex items-center gap-2 rounded-md px-2 py-1.5 text-xs text-sidebar-foreground/80 transition-colors hover:bg-white/10 hover:text-sidebar-accent-foreground"
                onClick={(e) => e.preventDefault()}
              >
                <LifeBuoy className="h-4 w-4 shrink-0 stroke-[2]" />
                Support
              </a>
              <a
                href="#"
                className="flex items-center gap-2 rounded-md px-2 py-1.5 text-xs text-sidebar-foreground/80 transition-colors hover:bg-white/10 hover:text-sidebar-accent-foreground"
                onClick={(e) => e.preventDefault()}
              >
                <BookOpen className="h-4 w-4 shrink-0 stroke-[2]" />
                Documentation
              </a>
            </div>
          </>
        ) : (
          <>
            <Button
              asChild
              size="icon"
              title="New scan"
              className="h-9 w-9 shrink-0 rounded-lg bg-sidebar-primary text-sidebar-primary-foreground hover:bg-sidebar-primary/90"
            >
              <Link to="/" aria-label="New scan">
                <Zap className="h-4 w-4 stroke-[2]" />
              </Link>
            </Button>
            <a
              href="#"
              title="Support"
              aria-label="Support"
              className="flex h-9 w-9 items-center justify-center rounded-md text-sidebar-foreground/80 transition-colors hover:bg-white/10 hover:text-sidebar-accent-foreground"
              onClick={(e) => e.preventDefault()}
            >
              <LifeBuoy className="h-4 w-4 stroke-[2]" />
            </a>
            <a
              href="#"
              title="Documentation"
              aria-label="Documentation"
              className="flex h-9 w-9 items-center justify-center rounded-md text-sidebar-foreground/80 transition-colors hover:bg-white/10 hover:text-sidebar-accent-foreground"
              onClick={(e) => e.preventDefault()}
            >
              <BookOpen className="h-4 w-4 stroke-[2]" />
            </a>
          </>
        )}
      </SidebarFooter>
    </Sidebar>
  );
}
