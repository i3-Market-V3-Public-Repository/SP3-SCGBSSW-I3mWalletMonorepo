export interface WalletFunctionMetadata {
    name: string;
    description?: string;
    call: string;
    scopes?: string[];
}
export interface WalletMetadata {
    name: string;
    features: {
        [feature: string]: any;
    };
    functions: WalletFunctionMetadata[];
}
//# sourceMappingURL=wallet-metadata.d.ts.map