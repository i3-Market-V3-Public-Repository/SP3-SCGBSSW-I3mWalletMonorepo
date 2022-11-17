import { Transport, WalletProtocol } from '@i3m/wallet-protocol';
export type CanBePromise<T> = Promise<T> | T;
export interface PinHtmlFormDialogOptions {
    overlayClass?: string;
    modalClass?: string;
    titleClass?: string;
    messageClass?: string;
    inputBoxClass?: string;
    inputClass?: string;
    buttonClass?: string;
}
export interface PinConsoleDialogOptions {
    message?: string;
}
export interface PinDialogOptions {
    htmlFormDialog?: PinHtmlFormDialogOptions;
    consoleDialog?: PinConsoleDialogOptions;
}
export interface SessionFileStorageOptions {
    filepath?: string;
    password?: string;
}
export interface SessionLocalStorageOptions {
    key?: string;
}
export interface SessionStorageOptions {
    fileStorage?: SessionFileStorageOptions;
    localStorage?: SessionLocalStorageOptions;
}
export interface SessionStorage {
    getSessionData: () => CanBePromise<any>;
    setSessionData: (json: any) => CanBePromise<void>;
    clear: () => CanBePromise<void>;
}
export interface SessionManagerOpts<T extends Transport = Transport> {
    protocol: WalletProtocol<T>;
    storageOptions?: SessionStorageOptions;
    storage?: SessionStorage;
}
export interface SessionManagerOptions {
    localStorageKey: string;
}
//# sourceMappingURL=types.d.ts.map