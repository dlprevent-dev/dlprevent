/** Confirmations in the dashboard's window instead of the browser's.
 *
 *  `window.confirm` brings along a box that looks like the operating system
 *  and not like this application: its own font, its own buttons, the name of
 *  the address above it — and it blocks the whole tab. Above all it cannot be
 *  styled: "Delete" and "Cancel" look the same in there, even though one of
 *  them shuts a device down and the other does nothing.
 *
 *  Hence the same pattern as for the notification bar (`toast` in
 *  `session.svelte.ts`): a piece of state here, a component in `App.svelte`
 *  that shows it. The caller gets a promise back — at the call site it reads
 *  the way it did before, only with `await`.
 *
 *  Deliberately **not** named `confirm`. Otherwise whoever extends the
 *  application will sooner or later write `if (!confirm(…)) return;` again,
 *  and because a promise is always truthy the question would come to nothing:
 *  the cancel would never arrive and the action would go through **always**.
 *  A different name rules exactly that out; `no_native_dialogs` in
 *  `tests/dialogs.test.mjs` pins it down. */

export type Ask = {
  title: string;
  /** What is about to happen. One sentence, not a paragraph. */
  body: string;
  /** What you should know before agreeing. Shown smaller underneath. */
  detail?: string;
  /** Label of the confirming button — "Delete", "Revoke", "Update". Never
   *  "OK": whoever skims the box reads only the button. */
  confirmLabel: string;
  /** Red, and cancel gets the focus. For anything that loses data or a
   *  device. */
  danger: boolean;
  resolve: (ok: boolean) => void;
};

export const dialog = $state<{ ask: Ask | null }>({ ask: null });

/** Ask for confirmation. `true` means agreed.
 *
 *  Escape, the cancel button and a click beside the box are the same thing:
 *  `false`. Doing nothing is thus always one key away. */
export function ask(o: { title: string; body: string; detail?: string; confirmLabel?: string; danger?: boolean }): Promise<boolean> {
  // One open question at a time. If a second one comes, the first counts as
  // declined — otherwise a promise would stay open forever and the caller
  // would wait in silence.
  dialog.ask?.resolve(false);
  return new Promise<boolean>((resolve) => {
    dialog.ask = {
      title: o.title,
      body: o.body,
      detail: o.detail,
      confirmLabel: o.confirmLabel ?? 'Confirm',
      danger: o.danger ?? false,
      resolve,
    };
  });
}

/** Called by the component once the user has decided. */
export function answer(ok: boolean): void {
  const open = dialog.ask;
  dialog.ask = null;
  open?.resolve(ok);
}
