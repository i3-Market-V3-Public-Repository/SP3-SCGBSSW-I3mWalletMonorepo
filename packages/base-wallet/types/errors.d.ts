interface HttpData {
    code?: number;
    status?: number;
}
export declare class WalletError extends Error {
    code: number;
    status: number;
    constructor(message: string, httpData?: HttpData);
}
export {};
//# sourceMappingURL=errors.d.ts.map