<script lang="ts">
  import type { Snippet } from 'svelte';
  let { title, actions }: { title: string; actions?: Snippet } = $props();
</script>

<div class="page-head">
  <div class="titles">
    <h1>{title}</h1>
  </div>
  {#if actions}<div class="actions">{@render actions()}</div>{/if}
</div>
