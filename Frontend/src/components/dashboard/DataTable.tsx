import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { useState } from "react";
import { Search } from "lucide-react";

interface Column<T> {
  key: keyof T | string;
  header: string;
  render?: (row: T) => React.ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  title?: string;
  searchable?: boolean;
  searchKeys?: string[];
  pageSize?: number;
}

export function DataTable<T extends Record<string, unknown>>({
  columns,
  data,
  title,
  searchable = false,
  searchKeys,
  pageSize = 10,
}: DataTableProps<T>) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);

  const filteredData = searchable
    ? data.filter((row) => {
        const keys = searchKeys || columns.map((c) => c.key as string);
        return keys.some((key) =>
          String(row[key] ?? "")
            .toLowerCase()
            .includes(search.toLowerCase())
        );
      })
    : data;

  const totalPages = Math.ceil(filteredData.length / pageSize);
  const pagedData = filteredData.slice(page * pageSize, (page + 1) * pageSize);

  return (
    <div className="rounded-xl border border-border bg-card overflow-hidden">
      {(title || searchable) && (
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-4 border-b border-border">
          {title && (
            <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide">
              {title}
            </h3>
          )}
          {searchable && (
            <div className="relative w-full sm:w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                placeholder="Search..."
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(0);
                }}
                className="pl-9 h-8 text-xs bg-secondary border-border"
              />
            </div>
          )}
        </div>
      )}
      <div className="overflow-x-auto scrollbar-thin">
        <Table>
          <TableHeader>
            <TableRow className="border-border hover:bg-transparent">
              {columns.map((col) => (
                <TableHead
                  key={String(col.key)}
                  className="text-[10px] uppercase tracking-widest text-muted-foreground font-semibold whitespace-nowrap"
                >
                  {col.header}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {pagedData.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="text-center text-muted-foreground py-12 text-sm"
                >
                  No data available — scan a domain to populate this table.
                </TableCell>
              </TableRow>
            ) : (
              pagedData.map((row, i) => (
                <TableRow
                  key={i}
                  className="border-border hover:bg-secondary/50 transition-colors"
                >
                  {columns.map((col) => (
                    <TableCell
                      key={String(col.key)}
                      className="text-xs text-foreground/80 whitespace-nowrap"
                    >
                      {col.render
                        ? col.render(row)
                        : String(row[col.key as string] ?? "")}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      {totalPages > 1 && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-border">
          <span className="text-xs text-muted-foreground">
            Page {page + 1} of {totalPages} ({filteredData.length} results)
          </span>
          <div className="flex gap-1">
            <button
              onClick={() => setPage(Math.max(0, page - 1))}
              disabled={page === 0}
              className="px-3 py-1 text-xs rounded-md bg-secondary text-secondary-foreground disabled:opacity-40 hover:bg-secondary/80 transition-colors"
            >
              Prev
            </button>
            <button
              onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
              disabled={page >= totalPages - 1}
              className="px-3 py-1 text-xs rounded-md bg-secondary text-secondary-foreground disabled:opacity-40 hover:bg-secondary/80 transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
