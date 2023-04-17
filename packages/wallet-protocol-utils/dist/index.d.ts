import { Transport, WalletProtocol, Session } from '@i3m/wallet-protocol';
import { Subject } from 'rxjs';

type CanBePromise<T> = Promise<T> | T;
interface PinHtmlFormDialogOptions {
    overlayClass?: string;
    modalClass?: string;
    titleClass?: string;
    messageClass?: string;
    inputBoxClass?: string;
    inputClass?: string;
    buttonClass?: string;
}
interface PinConsoleDialogOptions {
    message?: string;
}
interface PinDialogOptions {
    htmlFormDialog?: PinHtmlFormDialogOptions;
    consoleDialog?: PinConsoleDialogOptions;
}
interface SessionFileStorageOptions {
    filepath?: string;
    password?: string;
}
interface SessionLocalStorageOptions {
    key?: string;
}
interface SessionStorageOptions {
    fileStorage?: SessionFileStorageOptions;
    localStorage?: SessionLocalStorageOptions;
}
interface SessionStorage {
    getSessionData: () => CanBePromise<any>;
    setSessionData: (json: any) => CanBePromise<void>;
    clear: () => CanBePromise<void>;
}
interface SessionManagerOpts<T extends Transport = Transport> {
    protocol: WalletProtocol<T>;
    storageOptions?: SessionStorageOptions;
    storage?: SessionStorage;
}
interface SessionManagerOptions {
    localStorageKey: string;
}

declare const pinDialog: (opts?: PinDialogOptions) => Promise<string>;
declare const openModal: (opts?: PinDialogOptions) => Promise<string>;

declare class SessionManager<T extends Transport = Transport> {
    session: Session<T> | undefined;
    $session: Subject<Session<T> | undefined>;
    initialized: Promise<void>;
    protected storage: SessionStorage;
    protected protocol: WalletProtocol<T>;
    constructor(options: SessionManagerOpts<T>);
    private init;
    get hasSession(): boolean;
    fetch: Session<T>['send'];
    createIfNotExists(): Promise<Session<T>>;
    removeSession(): Promise<void>;
    setSession(session?: Session<T>): Promise<void>;
    loadSession(): Promise<void>;
}
declare class LocalSessionManager<T extends Transport = Transport> extends SessionManager<T> {
    protected protocol: WalletProtocol<T>;
    constructor(protocol: WalletProtocol<T>, options?: Partial<SessionManagerOptions>);
}

export { CanBePromise, LocalSessionManager, PinConsoleDialogOptions, PinDialogOptions, PinHtmlFormDialogOptions, SessionFileStorageOptions, SessionLocalStorageOptions, SessionManager, SessionManagerOptions, SessionManagerOpts, SessionStorage, SessionStorageOptions, openModal, pinDialog };
