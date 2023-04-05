import { VaultState } from './vault-state';
export type VaultEvent = {
    'state-changed': [
        state: VaultState
    ];
    'empty-storage': never;
    'storage-updated': [
        timestamp: number
    ];
    'storage-deleted': never;
    'sync-start': [
        startTime: number
    ];
    'sync-stop': [
        startTime: number,
        stopTime: number
    ];
};
export type VaultEventName = keyof VaultEvent;
export type ArgsForEvent<T extends VaultEventName> = VaultEvent[T];
//# sourceMappingURL=events.d.ts.map