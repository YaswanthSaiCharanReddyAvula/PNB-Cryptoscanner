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
  const { state } = useSidebar();
  const collapsed = state === "collapsed";
  const location = useLocation();

  const isActive = (path: string) =>
    path === "/" ? location.pathname === "/" : location.pathname.startsWith(path);

  return (
    <Sidebar
      collapsible="icon"
      className="border-r border-border bg-card"
    >
      <SidebarHeader className="border-b border-border px-4 py-4">
        <Link to="/" className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-border bg-secondary text-foreground">
            <ShieldCheck className="h-4 w-4" />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <p className="text-sm font-semibold text-foreground leading-tight">
                QuantumShield
              </p>
              <p className="text-[11px] text-muted-foreground leading-tight">
                Quantum‑safe migration platform
              </p>
            </div>
          )}
        </Link>
      </SidebarHeader>

      <SidebarContent className="px-2 py-4">
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu className="gap-0.5">
              {navItems.map((item) => {
                const active = isActive(item.url);
                return (
                  <SidebarMenuItem key={item.title}>
                    <SidebarMenuButton asChild isActive={active} tooltip={item.title}>
                      <NavLink
                        to={item.url}
                        end={item.url === "/"}
                        className={[
                          "flex items-center gap-3 rounded-lg px-3 py-2.5 text-[13px] font-medium transition-colors",
                          active
                            ? "bg-primary/10 text-primary"
                            : "text-muted-foreground hover:bg-secondary/60 hover:text-foreground",
                        ].join(" ")}
                        activeClassName=""
                      >
                        <item.icon className="h-4 w-4 shrink-0 opacity-90" />
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

      <SidebarFooter className="border-t border-border p-3">
        {!collapsed && (
          <Button
            asChild
            className="mb-3 w-full rounded-lg"
          >
            <Link to="/" className="gap-2 font-semibold">
              <Zap className="h-4 w-4" />
              New scan
            </Link>
          </Button>
        )}
        <div className="flex flex-col gap-1">
          <a
            href="#"
            className="flex items-center gap-2 rounded-md px-2 py-1.5 text-xs text-muted-foreground hover:text-foreground"
            onClick={(e) => e.preventDefault()}
          >
            <LifeBuoy className="h-3.5 w-3.5" />
            {!collapsed && "Support"}
          </a>
          <a
            href="#"
            className="flex items-center gap-2 rounded-md px-2 py-1.5 text-xs text-muted-foreground hover:text-foreground"
            onClick={(e) => e.preventDefault()}
          >
            <BookOpen className="h-3.5 w-3.5" />
            {!collapsed && "Documentation"}
          </a>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
