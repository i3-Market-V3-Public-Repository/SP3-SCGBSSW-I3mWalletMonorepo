import { PinDialogOptions } from './types'

/**
 * A PIN input dialog. In node is a promise that resolves to a PIN that is requested through the console to the end user. In browsers it shows an HTML formulary where to write the PIN, and returns a promise that resolves to that PIN when a user fills it and submits it.
 * @param opts
 * @returns a promise that resolves to the PIN
 */
export const pinDialog = async (opts?: PinDialogOptions): Promise<string> => {
  if (IS_BROWSER) {
    const pinHtmlFormDialog = await import('./pin-dialogs/pin-htmlform-dialog')
    return await pinHtmlFormDialog.pinHtmlFormDialog(opts?.htmlFormDialog)
  } else {
    const pinConsoleDialog = await import('./pin-dialogs/pin-console-dialog')
    return await pinConsoleDialog.pinConsoleDialog(opts?.consoleDialog)
  }
}

/**
 * A PIN input dialog. In node is a promise that resolves to a PIN that is requested through the console to the end user. In browsers it shows an HTML formulary where to write the PIN, and returns a promise that resolves to that PIN when a user fills it and submits it.
 * @deprecated Use {@link pinDialog} instead.
 * @param opts
 * @returns a promise that resolves to the PIN
 */
export const openModal = pinDialog
