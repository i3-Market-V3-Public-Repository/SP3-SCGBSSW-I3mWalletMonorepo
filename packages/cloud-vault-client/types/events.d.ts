export type VaultEvent = {
    connected: [
        timestamp?: number
    ];
    'disconnected': never;
    'unauthorized': never;
    'storage-updated': [
        timestamp: number
    ];
    'storage-deleted': never;
};
export type VaultEventName = keyof VaultEvent;
export type ArgsForEvent<T extends VaultEventName> = VaultEvent[T];
//# sourceMappingURL=events.d.ts.map