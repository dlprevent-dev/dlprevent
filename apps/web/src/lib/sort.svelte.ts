export interface SortState {
  key: string;
  asc: boolean;
  /** The direction the next click on this column will produce. */
  nextAsc(key: string): boolean;
  toggle(key: string): void;
}

export interface SortOptions {
  /** Starting direction. */
  asc?: boolean;
  /** A new column descending first: for times and amounts you want to see
   *  the largest at the top, not the smallest. */
  descFirst?: boolean;
  /** For server-side sorted tables: reload after the click. */
  onchange?: () => void;
}

/** Sort state of a table. A second click on the same column reverses the
 *  direction. */
export function createSort(key: string, opts: SortOptions = {}): SortState {
  const first = !opts.descFirst;
  const s = $state({
    key,
    asc: opts.asc ?? first,
    nextAsc(k: string) {
      return s.key === k ? !s.asc : first;
    },
    toggle(k: string) {
      s.asc = s.nextAsc(k);
      s.key = k;
      opts.onchange?.();
    },
  });
  return s;
}

/** Sorts a copy: numbers numerically, everything else as text. Empty values
 *  count as the smallest, so that both directions mirror each other. */
export function sortRows<T>(rows: T[], sort: SortState, value: (row: T, key: string) => unknown): T[] {
  const dir = sort.asc ? 1 : -1;
  return [...rows].sort((a, b) => {
    const x = value(a, sort.key), y = value(b, sort.key);
    const xe = x === null || x === undefined || x === '', ye = y === null || y === undefined || y === '';
    if (xe || ye) return xe && ye ? 0 : (xe ? -1 : 1) * dir;
    if (typeof x === 'number' && typeof y === 'number') return (x - y) * dir;
    if (typeof x === 'boolean' && typeof y === 'boolean') return (Number(x) - Number(y)) * dir;
    return String(x).localeCompare(String(y), 'en', { numeric: true, sensitivity: 'base' }) * dir;
  });
}

/** Full-text search in the browser: every word has to occur somewhere. */
export function matches(haystack: string, query: string): boolean {
  const h = haystack.toLowerCase();
  return query.toLowerCase().split(/\s+/).filter(Boolean).every((w) => h.includes(w));
}
