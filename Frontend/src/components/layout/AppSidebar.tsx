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
      className="border-r border-slate-800/50"
      style={{ backgroundColor: "#0b1220" }}
    >
      <SidebarHeader className="border-b border-white/5 px-4 py-5">
        <Link to="/" className="flex flex-col gap-0.5">
          <span className="text-[10px] font-semibold uppercase tracking-[0.25em] text-slate-500">
            The Sentinel
          </span>
          {!collapsed && (
            <span className="text-xs font-medium leading-snug text-slate-300">
              Intelligence Dossier
            </span>
          )}
        </Link>
        {!collapsed && (
          <div className="mt-3 flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600/20 text-blue-400">
              <ShieldCheck className="h-4 w-4" />
            </div>
            <div>
              <p className="text-sm font-semibold text-white">QuantumShield</p>
              <p className="text-[10px] text-slate-500">Crypto resilience</p>
            </div>
          </div>
        )}
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
                            ? "bg-white/[0.08] text-white shadow-[inset_3px_0_0_0_#3b82f6]"
                            : "text-slate-400 hover:bg-white/[0.04] hover:text-slate-200",
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

      <SidebarFooter className="border-t border-white/5 p-3">
        {!collapsed && (
          <Button
            asChild
            className="mb-3 w-full rounded-lg bg-white text-slate-900 hover:bg-slate-100"
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
            className="flex items-center gap-2 rounded-md px-2 py-1.5 text-xs text-slate-500 hover:text-slate-300"
            onClick={(e) => e.preventDefault()}
          >
            <LifeBuoy className="h-3.5 w-3.5" />
            {!collapsed && "Support"}
          </a>
          <a
            href="#"
            className="flex items-center gap-2 rounded-md px-2 py-1.5 text-xs text-slate-500 hover:text-slate-300"
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
