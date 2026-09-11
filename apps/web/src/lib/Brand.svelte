<script lang="ts">
  import logo from '../assets/dlprevent-logo.svg';
  import icon from '../assets/dlprevent-icon.svg';

  let { compact = false }: { compact?: boolean } = $props();
</script>

<div class="brand" class:compact>
  <div class="brand-art"><img src={compact ? icon : logo} alt="DLPrevent" /></div>
  {#if !compact}<span class="sub">Central</span>{/if}
</div>

<style>
  /* A light brand panel keeps the graphite wordmark readable in dark mode too. */
  .brand { min-width: 0; max-width: 100%; }
  .brand-art { width: 100%; min-width: 0; background: #faf8f4; }
  img { display: block; width: 100%; max-width: 100%; height: auto; object-fit: contain; }
  .brand.compact { width: 32px; padding: 0; border: 0; }
</style>
