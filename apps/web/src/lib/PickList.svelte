<script lang="ts">
  /// Picking from a list that is too long to page through.
  ///
  /// Built for customer environments: tens of thousands of groups never make
  /// it into the browser in full. Pass a remote source and you get a
  /// server-side search with a limit; pass a fixed list and it is filtered in
  /// the browser. From the outside both look the same.
  interface Item { value: string; label: string; hint?: string; tag?: string }

  let {
    items = [],
    search,
    selected = $bindable<string[]>([]),
    multiple = false,
    placeholder = 'Search…',
    empty = 'Nothing found.',
    disabled = false,
    id,
    onselect,
  }: {
    /// Fixed list (the browser filters). Leave empty when `search` is set.
    items?: Item[];
    /// Remote search; returns the matches for the input.
    search?: (q: string) => Promise<Item[]>;
    selected?: string[];
    multiple?: boolean;
    placeholder?: string;
    empty?: string;
    disabled?: boolean;
    id?: string;
    /// Called after every change with the new selection — for cases where
    /// the selection ends up somewhere other than in `selected`.
    onselect?: (values: string[]) => void;
  } = $props();

  let q = $state('');
  let open = $state(false);
  let loading = $state(false);
  let remote = $state<Item[]>([]);
  let active = $state(0);
  let box: HTMLDivElement;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const shown = $derived.by(() => {
    if (search) return remote;
    const needle = q.trim().toLowerCase();
    const all = needle
      ? items.filter((i) => i.label.toLowerCase().includes(needle) || (i.hint ?? '').toLowerCase().includes(needle))
      : items;
    // The fixed list is capped too: a file server can have hundreds of
    // shares, and nobody wants to see them all at once.
    return all.slice(0, 100);
  });

  /// The remote search is debounced: one query per keystroke would be rude
  /// to the central server in a large domain.
  function onInput() {
    active = 0;
    if (!search) return;
    clearTimeout(timer);
    loading = true;
    timer = setTimeout(async () => {
      try { remote = await search(q); } catch { remote = []; }
      loading = false;
    }, 180);
  }

  function show() {
    if (disabled) return;
    open = true;
    if (search && remote.length === 0) onInput();
  }

  function pick(item: Item) {
    if (multiple) {
      if (!selected.includes(item.value)) selected = [...selected, item.value];
      q = '';
      if (search) onInput();
      onselect?.(selected);
    } else {
      selected = [item.value];
      q = '';
      open = false;
      onselect?.(selected);
    }
  }

  function remove(v: string) {
    selected = selected.filter((s) => s !== v);
    onselect?.(selected);
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === 'ArrowDown') { e.preventDefault(); open = true; active = Math.min(active + 1, shown.length - 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); active = Math.max(active - 1, 0); }
    else if (e.key === 'Enter' && open && shown[active]) { e.preventDefault(); pick(shown[active]); }
    else if (e.key === 'Escape') { open = false; }
    else if (e.key === 'Backspace' && q === '' && multiple && selected.length) { remove(selected[selected.length - 1]); }
  }

  $effect(() => {
    function away(e: MouseEvent) { if (box && !box.contains(e.target as Node)) open = false; }
    document.addEventListener('mousedown', away);
    return () => document.removeEventListener('mousedown', away);
  });
</script>

<div class="pick" bind:this={box} class:disabled>
  {#if multiple && selected.length}
    <div class="chips">
      {#each selected as s (s)}
        <span class="chip">{s}<button type="button" class="x" onclick={() => remove(s)} aria-label="Remove {s}">×</button></span>
      {/each}
    </div>
  {/if}
  <input
    {id}
    type="text"
    autocomplete="off"
    {placeholder}
    {disabled}
    bind:value={q}
    oninput={onInput}
    onfocus={show}
    onkeydown={onKey} />
  {#if !multiple && selected.length && !q}
    <div class="chosen mono">{selected[0]}<button type="button" class="x" onclick={() => { selected = []; onselect?.(selected); }} aria-label="Clear">×</button></div>
  {/if}
  {#if open}
    <div class="drop" role="listbox">
      {#if loading}
        <div class="none">Searching…</div>
      {:else if shown.length === 0}
        <div class="none">{empty}</div>
      {:else}
        {#each shown as i, n (i.value)}
          <button
            type="button"
            role="option"
            aria-selected={selected.includes(i.value)}
            class="opt"
            class:active={n === active}
            class:on={selected.includes(i.value)}
            onmouseenter={() => (active = n)}
            onclick={() => pick(i)}>
            <span class="l">{i.label}</span>
            {#if i.tag}<span class="tag">{i.tag}</span>{/if}
            {#if i.hint}<span class="h mono">{i.hint}</span>{/if}
          </button>
        {/each}
        {#if shown.length >= 50}<div class="none">Showing the first {shown.length}. Narrow the search to see others.</div>{/if}
      {/if}
    </div>
  {/if}
</div>

<style>
  .pick { position: relative; }
  .pick.disabled { opacity: 0.55; }
  .chips { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 6px; }
  .chip, .chosen {
    display: inline-flex; align-items: center; gap: 6px; padding: 2px 6px;
    border-radius: 0; background: var(--accent-2); color: var(--accent);
    font-family: var(--font-mono); font-size: 11px; box-shadow: inset 0 0 0 1px var(--accent-3);
  }
  .chosen { margin-top: 6px; }
  .x { border: 0; background: none; color: inherit; cursor: pointer; padding: 0; font-size: 14px; line-height: 1; opacity: 0.7; }
  .x:hover { opacity: 1; }
  .drop {
    position: absolute; z-index: 30; left: 0; right: 0; margin-top: 4px; max-height: 260px; overflow-y: auto;
    background: var(--panel); border: 1px solid var(--border-strong); border-radius: 0; box-shadow: var(--shadow-2);
  }
  .opt {
    display: grid; grid-template-columns: 1fr auto; gap: 2px 8px; width: 100%; text-align: left;
    padding: 6px 10px; border: 0; background: none; color: inherit; cursor: pointer; font: inherit;
  }
  .opt .h { grid-column: 1 / -1; font-size: 11px; color: var(--muted); }
  .opt .tag { font-size: 11px; color: var(--muted); }
  .opt.active { background: var(--panel-2); }
  .opt.on .l { color: var(--accent); }
  .none { padding: 8px 10px; font-size: 12px; color: var(--muted); }
</style>
