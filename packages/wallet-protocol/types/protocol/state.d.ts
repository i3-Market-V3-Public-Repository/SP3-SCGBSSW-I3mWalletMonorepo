export interface Identity {
    name: string;
    url?: string;
}
export interface PKEData {
    id: Identity;
    rx: Uint8Array;
    publicKey: string;
}
export interface ProtocolPKEData {
    a: PKEData;
    b: PKEData;
    port: number;
    sent: PKEData;
    received: PKEData;
}
export interface AuthData {
    cx: Uint8Array;
    nx: Uint8Array;
    r: Uint8Array;
}
export interface ProtocolAuthData {
    a: AuthData;
    b: AuthData;
    sent: AuthData;
    received: AuthData;
}
//# sourceMappingURL=state.d.ts.map