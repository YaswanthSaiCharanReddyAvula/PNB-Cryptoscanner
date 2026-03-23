import {
  Home,
  Server,
  Network,
  ShieldCheck,
  Lock,
  Star,
  FileText,
} from "lucide-react";
import { NavLink } from "@/components/NavLink";
import { useLocation } from "react-router-dom";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarHeader,
  useSidebar,
} from "@/components/ui/sidebar";

const GOLD = "#FBBC09";
const MAROON = "#6B0020";

const navItems = [
  { title: "Home", url: "/", icon: Home },
  { title: "Asset Inventory", url: "/asset-inventory", icon: Server },
  { title: "Asset Discovery", url: "/asset-discovery", icon: Network },
  { title: "CBOM", url: "/cbom", icon: ShieldCheck },
  { title: "PQC Posture", url: "/pqc-posture", icon: Lock },
  { title: "Cyber Rating", url: "/cyber-rating", icon: Star },
  { title: "Reporting", url: "/reporting", icon: FileText },
];

// Mini PQC shield for sidebar header
function SidebarShield({ collapsed }: { collapsed: boolean }) {
  return (
    <div className="flex items-center gap-3">
      <svg
        width={collapsed ? 30 : 34}
        height={collapsed ? 34 : 38}
        viewBox="0 0 44 50"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="flex-shrink-0"
      >
        <path
          d="M22 2L4 9.5V23C4 33.5 12 42.8 22 47C32 42.8 40 33.5 40 23V9.5L22 2Z"
          fill={MAROON}
          stroke={GOLD}
          strokeWidth="2.5"
        />
        <path d="M22 2L4 9.5V14L22 7L40 14V9.5L22 2Z" fill={GOLD} opacity="0.9" />
        <text x="22" y="28" textAnchor="middle" fill={GOLD} fontSize="8" fontWeight="bold" fontFamily="monospace" letterSpacing="1">PNB</text>
        <text x="22" y="37" textAnchor="middle" fill="white" fontSize="4.5" fontFamily="sans-serif" letterSpacing="0.5">PQC-READY</text>
      </svg>
      {!collapsed && (
        <div className="flex flex-col leading-tight">
          <span className="text-sm font-bold" style={{ color: GOLD }}>QSCAS</span>
          <span className="text-[9px]" style={{ color: `${GOLD}99` }}>Quantum-Safe Platform</span>
        </div>
      )}
    </div>
  );
}

export function AppSidebar() {
  const { state } = useSidebar();
  const collapsed = state === "collapsed";
  const location = useLocation();

  const isActive = (path: string) =>
    path === "/" ? location.pathname === "/" : location.pathname.startsWith(path);

  return (
    <Sidebar
      collapsible="icon"
      className="border-r-0"
      style={{ backgroundColor: MAROON }}
    >
      <SidebarHeader
        className="p-4"
        style={{ backgroundColor: MAROON }}
      >
        <SidebarShield collapsed={collapsed} />
      </SidebarHeader>

      <SidebarContent style={{ backgroundColor: MAROON }}>
        <SidebarGroup>
          {!collapsed && (
            <SidebarGroupLabel
              className="text-[10px] uppercase tracking-widest font-semibold px-3 pt-2 pb-1"
              style={{ color: `${GOLD}80` }}
            >
              Navigation
            </SidebarGroupLabel>
          )}
          <SidebarGroupContent>
            <SidebarMenu className="gap-2 px-2">
              {navItems.map((item) => {
                const active = isActive(item.url);
                return (
                  <SidebarMenuItem key={item.title}>
                    <SidebarMenuButton
                      asChild
                      isActive={active}
                      tooltip={item.title}
                      className="hover:bg-transparent"
                    >
                      <NavLink
                        to={item.url}
                        end={item.url === "/"}
                        className="flex items-center gap-4 px-4 py-3 rounded-xl transition-all duration-200 text-[15px]"
                        style={
                          active
                            ? {
                                backgroundColor: GOLD,
                                color: MAROON,
                                fontWeight: 700,
                              }
                            : {
                                color: "#dfa0a0", // Soft muted pinkish for inactive text
                              }
                        }
                        activeClassName=""
                      >
                        <item.icon
                          className="h-5 w-5 flex-shrink-0"
                          style={{ color: active ? MAROON : GOLD }}
                        />
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
    </Sidebar>
  );
}
