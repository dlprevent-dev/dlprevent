<script lang="ts">
  import Icon from './Icon.svelte';
  import type { SortState } from './sort.svelte';
  let { sort, key, label, num = false }: { sort: SortState; key: string; label: string; num?: boolean } = $props();
  const on = $derived(sort.key === key);
  // On hover the arrow shows what the click will do, and afterwards how the
  // table is sorted.
  const up = $derived(on ? sort.asc : sort.nextAsc(key));
</script>

<th class:num class:sorted={on} aria-sort={on ? (sort.asc ? 'ascending' : 'descending') : 'none'}>
  <button class="sortbtn" onclick={() => sort.toggle(key)} title="Sort by {label}">
    {label}<span class="arrow"><Icon name={up ? 'up' : 'down'} size={13} /></span>
  </button>
</th>
