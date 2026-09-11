<script lang="ts">
  import Icon from './Icon.svelte';
  let { value = $bindable(''), placeholder = 'Search…', oninput }:
    { value?: string; placeholder?: string; oninput?: () => void } = $props();
</script>

<div class="search">
  <span class="ico"><Icon name="search" size={15} /></span>
  <input type="search" {placeholder} bind:value oninput={() => oninput?.()} aria-label={placeholder} />
  {#if value}
    <button class="iconbtn clear" aria-label="Clear search" onclick={() => { value = ''; oninput?.(); }}><Icon name="x" size={14} /></button>
  {/if}
</div>
