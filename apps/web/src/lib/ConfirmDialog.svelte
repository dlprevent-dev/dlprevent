<script lang="ts">
  /* Shows the open confirmation from `confirm.svelte.ts`. Mounted once in
     `App.svelte`, not per page: there is one question at a time, and no page
     has to manage a dialog that does not belong to it. */
  import Modal from './Modal.svelte';
  import { dialog, answer } from './confirm.svelte';

  const a = $derived(dialog.ask);

  /* Focus lands where the Enter key breaks nothing: on cancel for a
     consequential question, otherwise on the confirmation. */
  function focusIf(el: HTMLButtonElement, on: boolean) { if (on) el.focus(); }
</script>

{#if a}
  <Modal title={a.title} onclose={() => answer(false)}>
    <p class="ask-body">{a.body}</p>
    {#if a.detail}<p class="muted small ask-detail">{a.detail}</p>{/if}
    {#snippet actions()}
      <button type="button" class="btn" use:focusIf={a.danger} onclick={() => answer(false)}>Cancel</button>
      <button type="button" class="btn {a.danger ? 'danger' : 'primary'}" use:focusIf={!a.danger} onclick={() => answer(true)}>
        {a.confirmLabel}
      </button>
    {/snippet}
  </Modal>
{/if}

<style>
  /* The body of a confirmation is one sentence, not body copy: no outer
     margins that pull the heading and the buttons apart. */
  .ask-body { margin: 0; white-space: pre-line; }
  .ask-detail { margin: 10px 0 0; white-space: pre-line; }
</style>
