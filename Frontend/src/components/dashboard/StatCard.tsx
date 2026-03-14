import { motion } from "framer-motion";
import { LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  variant?: "default" | "gold" | "red" | "success" | "info";
}

const variantStyles = {
  default: "border-border",
  gold: "border-primary/30 card-glow-gold",
  red: "border-accent/30 card-glow-red",
  success: "border-success/30",
  info: "border-info/30",
};

const iconVariantStyles = {
  default: "bg-muted text-muted-foreground",
  gold: "bg-primary/15 text-primary",
  red: "bg-accent/15 text-accent",
  success: "bg-success/15 text-success",
  info: "bg-info/15 text-info",
};

export function StatCard({ title, value, icon: Icon, trend, variant = "default" }: StatCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -2 }}
      transition={{ duration: 0.2 }}
      className={`rounded-xl border bg-card p-5 ${variantStyles[variant]} transition-all duration-300 hover:shadow-lg`}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-1.5">
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {title}
          </p>
          <p className="text-2xl font-bold text-foreground">{value}</p>
          {trend && (
            <p className="text-xs text-muted-foreground">{trend}</p>
          )}
        </div>
        <div className={`rounded-lg p-2.5 ${iconVariantStyles[variant]}`}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </motion.div>
  );
}
