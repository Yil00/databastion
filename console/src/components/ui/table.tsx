import type { HTMLAttributes, TdHTMLAttributes, ThHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export function Table({ className, ...props }: HTMLAttributes<HTMLTableElement>) {
  return (
    <div className="relative w-full overflow-x-auto">
      <table className={cn("w-full caption-bottom text-sm", className)} {...props} />
    </div>
  );
}
export const TableHeader = (p: HTMLAttributes<HTMLTableSectionElement>) => <thead className="[&_tr]:border-b" {...p} />;
export const TableBody = (p: HTMLAttributes<HTMLTableSectionElement>) => <tbody className="[&_tr:last-child]:border-0" {...p} />;
export const TableRow = ({ className, ...p }: HTMLAttributes<HTMLTableRowElement>) => (
  <tr className={cn("border-b transition-colors hover:bg-muted/50", className)} {...p} />
);
export const TableHead = ({ className, ...p }: ThHTMLAttributes<HTMLTableCellElement>) => (
  <th className={cn("h-10 px-2 text-left align-middle font-medium whitespace-nowrap text-foreground", className)} {...p} />
);
export const TableCell = ({ className, ...p }: TdHTMLAttributes<HTMLTableCellElement>) => (
  <td className={cn("p-2 align-middle whitespace-nowrap", className)} {...p} />
);
