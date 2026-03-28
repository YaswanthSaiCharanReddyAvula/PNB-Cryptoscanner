import { ReactNode } from "react";

type Props = {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
};

export function DossierPageHeader({ eyebrow, title, description, actions }: Props) {
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between pb-6 border-b border-slate-200/80">
      <div className="space-y-1">
        {eyebrow && (
          <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">
            {eyebrow}
          </p>
        )}
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 md:text-3xl">{title}</h1>
        {description && (
          <p className="max-w-3xl text-sm leading-relaxed text-slate-600">{description}</p>
        )}
      </div>
      {actions ? <div className="flex flex-shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
