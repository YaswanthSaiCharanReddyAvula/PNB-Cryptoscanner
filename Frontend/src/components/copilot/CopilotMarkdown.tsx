import {
  useEffect,
  useId,
  useRef,
  type ComponentPropsWithoutRef,
  type ComponentType,
} from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeRaw from "rehype-raw";
import rehypeSanitize, { defaultSchema } from "rehype-sanitize";
import type { Components } from "react-markdown";
import {
  AlertTriangle,
  BarChart3,
  CheckCircle,
  FileText,
  Flag,
  GitBranch,
  LayoutDashboard,
  ListTree,
  PieChart,
  Search,
  Shield,
  Wrench,
  type LucideProps,
} from "lucide-react";
import { cn } from "@/lib/utils";

/** Maps [Icon: Name] tags (MUI-style labels in LLM output) to Lucide icons. */
const COPILOT_ICON_MAP: Record<string, ComponentType<LucideProps>> = {
  Dashboard: LayoutDashboard,
  BarChart: BarChart3,
  PieChart,
  Security: Shield,
  Warning: AlertTriangle,
  Search,
  Build: Wrench,
  AccountTree: ListTree,
  PriorityHigh: Flag,
  Report: FileText,
  CheckCircle,
  Mermaid: GitBranch,
};

const iconClassRegex = /^copilot-icon ci-([A-Za-z][A-Za-z0-9_]*)$/;

function resolveCopilotIcon(name: string): ComponentType<LucideProps> {
  return COPILOT_ICON_MAP[name] ?? COPILOT_ICON_MAP.Dashboard;
}

/**
 * Replace `[Icon: Foo]` with a span that uses only allowlisted class names so rehype-sanitize keeps it.
 */
export function injectCopilotIconPlaceholders(markdown: string): string {
  return markdown.replace(
    /\[Icon:\s*([A-Za-z][A-Za-z0-9_]*)\]/g,
    (_full, name: string) => `<span class="copilot-icon ci-${name}"></span>`,
  );
}

const copilotSanitizeSchema = {
  ...defaultSchema,
  attributes: {
    ...defaultSchema.attributes,
    span: [
      ...(defaultSchema.attributes?.span || []),
      ["className", iconClassRegex],
    ],
  },
};

function MermaidBlock({ chart }: { chart: string }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const reactId = useId().replace(/:/g, "");

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    let cancelled = false;
    void import("mermaid").then(async (mermaidMod) => {
      const mermaid = mermaidMod.default;
      const isDark = document.documentElement.classList.contains("dark");
      mermaid.initialize({
        startOnLoad: false,
        theme: isDark ? "dark" : "default",
        securityLevel: "loose",
        fontFamily: "inherit",
      });
      try {
        const { svg } = await mermaid.render(`copilot-mmd-${reactId}`, chart.trim());
        if (!cancelled) el.innerHTML = svg;
      } catch {
        if (!cancelled) el.textContent = chart;
      }
    });
    return () => {
      cancelled = true;
    };
  }, [chart, reactId]);

  return (
    <div
      ref={containerRef}
      className="my-2 overflow-x-auto rounded-md border border-border/60 bg-muted/30 p-2 text-foreground [&_svg]:h-auto [&_svg]:max-w-full"
    />
  );
}

function CopilotIconSpan({
  className,
  ...rest
}: ComponentPropsWithoutRef<"span">) {
  const cls = Array.isArray(className) ? className.join(" ") : String(className || "");
  const m = iconClassRegex.exec(cls.trim());
  if (m) {
    const Icon = resolveCopilotIcon(m[1]);
    return (
      <span
        className="inline-flex h-[1.1em] w-[1.1em] shrink-0 items-center justify-center align-[-0.15em] text-primary [&>svg]:h-full [&>svg]:w-full"
        title={m[1]}
        aria-hidden
        {...rest}
      >
        <Icon strokeWidth={2} />
      </span>
    );
  }
  return (
    <span className={className} {...rest} />
  );
}

function buildComponents(): Components {
  return {
    pre: ({ children }) => <>{children}</>,
    span: ({ className, children, ...rest }) => (
      <CopilotIconSpan className={className} {...rest}>
        {children}
      </CopilotIconSpan>
    ),
    code({ className, children, ...rest }) {
      const match = /language-(\w+)/.exec(className || "");
      const lang = match?.[1];
      const code = String(children).replace(/\n$/, "");
      if (lang === "mermaid") {
        return <MermaidBlock chart={code} />;
      }
      if (className?.includes("language-")) {
        return (
          <pre className="my-2 overflow-x-auto rounded-md border border-border/40 bg-muted/40 p-2 text-[11px] leading-relaxed">
            <code className={cn("font-mono", className)} {...rest}>
              {children}
            </code>
          </pre>
        );
      }
      return (
        <code
          className={cn("rounded bg-muted/80 px-1 py-0.5 font-mono text-[11px]", className)}
          {...rest}
        >
          {children}
        </code>
      );
    },
  };
}

const copilotMarkdownComponents = buildComponents();

export function CopilotMarkdown({ content }: { content: string }) {
  const processed = injectCopilotIconPlaceholders(content);

  return (
    <div className="prose prose-sm dark:prose-invert max-w-none text-left text-foreground [&_blockquote]:border-l-primary [&_blockquote]:text-muted-foreground [&_h3]:mb-2 [&_h3]:mt-3 [&_h3]:flex [&_h3]:flex-wrap [&_h3]:items-center [&_h3]:gap-x-1.5 [&_h3]:gap-y-1 [&_h3]:text-sm [&_h3]:font-semibold [&_li]:my-0.5 [&_p]:my-1 [&_ul]:my-1">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeRaw, [rehypeSanitize, copilotSanitizeSchema]]}
        components={copilotMarkdownComponents}
      >
        {processed}
      </ReactMarkdown>
    </div>
  );
}
