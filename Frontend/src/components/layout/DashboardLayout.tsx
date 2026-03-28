import { SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "./AppSidebar";
import { TopNavbar } from "./TopNavbar";

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <SidebarProvider>
      <div className="dossier-layout flex min-h-screen w-full">
        <AppSidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <TopNavbar />
          <main className="scrollbar-thin flex-1 overflow-auto p-4 md:p-8">
            <div className="mx-auto max-w-[1600px]">{children}</div>
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
