<script lang="ts">
  // A set of line icons, 24-unit grid, inherits the text colour. Inline,
  // because the CSP only allows our own sources.
  const paths: Record<string, string> = {
    overview: 'M4 13h7V4H4zM13 20h7v-9h-7zM4 20h7v-4H4zM13 8h7V4h-7z',
    alert: 'M12 4 2.8 20h18.4zM12 10v4M12 17.5v.5',
    rules: 'M4 7h16M4 12h16M4 17h10M2.5 7h.01M2.5 12h.01M2.5 17h.01',
    agents: 'M3 5h18v11H3zM8 20h8M12 16v4',
    sources: 'M3 5h18v6H3zM3 13h18v6H3zM7 8h.01M7 16h.01',
    users: 'M9 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7ZM2.5 20a6.5 6.5 0 0 1 13 0M17 11a3 3 0 1 0 0-6M18 14.5a5.5 5.5 0 0 1 3.5 5.5',
    settings: 'M5 6h14M5 12h14M5 18h14M9 6a1.6 1.6 0 1 0 0-.01M15 12a1.6 1.6 0 1 0 0-.01M8 18a1.6 1.6 0 1 0 0-.01',
    audit: 'M8 3h8v3H8zM6.5 5H5v16h14V5h-1.5M8.5 11h7M8.5 15h4',
    shield: 'M12 3 4.5 6v5.5c0 4.4 3 8 7.5 9.5 4.5-1.5 7.5-5.1 7.5-9.5V6z',
    search: 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14ZM20 20l-4-4',
    x: 'M6 6l12 12M18 6 6 18',
    plus: 'M12 5v14M5 12h14',
    trash: 'M4 7h16M9.5 7V4.5h5V7M6.5 7l1 13h9l1-13M10 11v6M14 11v6',
    edit: 'M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17zM15 6l3 3',
    check: 'M5 12.5 10 17.5 19.5 7',
    copy: 'M9 9h11v11H9zM5 15H4V4h11v1',
    logout: 'M15 4h4v16h-4M12 8l4 4-4 4M16 12H4',
    up: 'M6 14l6-6 6 6',
    down: 'M6 10l6 6 6-6',
    folder: 'M3 6h6l2 2.5h10V19H3z',
    refresh: 'M20 12a8 8 0 1 1-2.6-5.9M20 4v4.5h-4.5',
    key: 'M14.5 4a5.5 5.5 0 1 1-4.6 8.5L4 18.5V21h3l.5-2h2l.5-2h2l1.4-1.4A5.5 5.5 0 0 1 14.5 4ZM16.5 8.5h.01',
    chart: 'M4 20V10M9.5 20V4M15 20v-7M20.5 20v-4',
    lock: 'M6 11h12v9H6zM8.5 11V8a3.5 3.5 0 0 1 7 0v3',
    mail: 'M3 6h18v12H3zM3 6.5l9 6.5 9-6.5',
    ok: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM8 12.5l2.6 2.5L16 9.5',
  };
  let { name, size = 16, stroke = 1.7 }: { name: string; size?: number; stroke?: number } = $props();
</script>

<svg class="svg-icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
     stroke-width={stroke} stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
  <path d={paths[name] ?? ''} />
</svg>
