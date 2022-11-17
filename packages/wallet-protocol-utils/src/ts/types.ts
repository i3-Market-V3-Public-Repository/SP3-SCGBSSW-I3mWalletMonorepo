import { Transport, WalletProtocol } from '@i3m/wallet-protocol'

export type CanBePromise<T> = Promise<T> | T

export interface PinHtmlFormDialogOptions {
  overlayClass?: string
  modalClass?: string
  titleClass?: string
  messageClass?: string
  inputBoxClass?: string
  inputClass?: string
  buttonClass?: string
}

export interface PinConsoleDialogOptions {
  message?: string // The message used when requesting the PIN
}

export interface PinDialogOptions {
  htmlFormDialog?: PinHtmlFormDialogOptions
  consoleDialog?: PinConsoleDialogOptions
}

export interface SessionFileStorageOptions {
  filepath?: string // a path to the file that will be used to store wallet session data
  password?: string // if provided a key will be derived from the password and the store file will be encrypted
}

export interface SessionLocalStorageOptions {
  key?: string
}

export interface SessionStorageOptions {
  fileStorage?: SessionFileStorageOptions
  localStorage?: SessionLocalStorageOptions
}

export interface SessionStorage {
  getSessionData: () => CanBePromise<any> // gets JSON object with the session data
  setSessionData: (json: any) => CanBePromise<void>
  clear: () => CanBePromise<void>
}

export interface SessionManagerOpts<T extends Transport = Transport> {
  protocol: WalletProtocol<T> // a protocol already created using the @i3m/wallet-protocol
  storageOptions?: SessionStorageOptions // ignored is storage is provided. Defines options for the default storages in browser (LocalStorage) and Node.js (FileStorage)
  storage?: SessionStorage // an optional session storage
}

/**
 * @deprecated. It will be removed in the next major release
 */
export interface SessionManagerOptions {
  localStorageKey: string
}
