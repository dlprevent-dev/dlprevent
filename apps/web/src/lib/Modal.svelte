<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';
  let { title, subtitle = '', wide = false, onclose, children, actions }:
    { title: string; subtitle?: string; wide?: boolean; onclose: () => void; children: Snippet; actions?: Snippet } = $props();
  function bg(e: MouseEvent) { if (e.target === e.currentTarget) onclose(); }
  function keys(e: KeyboardEvent) { if (e.key === 'Escape') { e.preventDefault(); onclose(); } }
</script>

<svelte:window onkeydown={keys} />
<div class="modal-bg" onclick={bg} role="presentation">
  <div class="modal" class:wide role="dialog" aria-modal="true" aria-label={title}>
    <header>
      <div>
        <h2>{title}</h2>
        {#if subtitle}<div class="muted small">{subtitle}</div>{/if}
      </div>
      <span class="spacer"></span>
      <button class="iconbtn" onclick={onclose} aria-label="Close"><Icon name="x" /></button>
    </header>
    <div class="body">{@render children()}</div>
    {#if actions}<div class="actions">{@render actions()}</div>{/if}
  </div>
</div>
