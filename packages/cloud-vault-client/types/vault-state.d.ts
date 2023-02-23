export declare const VAULT_STATE: {
    readonly NOT_INITIALIZED: 0;
    readonly INITIALIZED: 1;
    readonly LOGGED_IN: 2;
    readonly CONNECTED: 3;
};
export type VaultState = typeof VAULT_STATE['NOT_INITIALIZED'] | typeof VAULT_STATE['INITIALIZED'] | typeof VAULT_STATE['LOGGED_IN'] | typeof VAULT_STATE['CONNECTED'];
export declare function stateFromError(currentState: VaultState, error: unknown): VaultState;
//# sourceMappingURL=vault-state.d.ts.map