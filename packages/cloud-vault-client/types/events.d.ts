import { VaultError } from './error';
export type VaultEvent = {
    connected: [
        timestamp?: number
    ];
    'logged-out': never;
    'storage-updated': [
        timestamp: number
    ];
    'storage-deleted': never;
    'connection-error': [
        error: VaultError
    ];
};
export type VaultEventName = keyof VaultEvent;
export type ArgsForEvent<T extends VaultEventName> = VaultEvent[T];
//# sourceMappingURL=events.d.ts.map