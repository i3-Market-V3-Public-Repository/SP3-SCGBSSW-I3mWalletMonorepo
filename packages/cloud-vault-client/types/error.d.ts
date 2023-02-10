export type VaultErrorData = {
    'not-initialized': any;
    'http-connection-error': {
        request: {
            method?: string;
            url?: string;
            headers?: {
                [header: string]: string;
            };
            data?: any;
        };
        response?: {
            status?: number;
            headers?: {
                [header: string]: string;
            };
            data?: any;
        };
    };
    'no-uploadded-storage': any;
    'sse-connection-error': Event;
    conflict: {
        localTimestamp?: number;
        remoteTimestamp?: number;
    };
    unauthorized: any;
    error: any;
    unknown: any;
    validation: {
        description?: string;
        data?: any;
    };
};
type VaultErrorName = keyof VaultErrorData;
type DataForError<T extends VaultErrorName> = VaultErrorData[T];
export declare class VaultError<T extends VaultErrorName = VaultErrorName> extends Error {
    data: any;
    message: T;
    constructor(message: T, data: DataForError<T>, options?: ErrorOptions);
    static from(error: unknown): VaultError;
}
export {};
//# sourceMappingURL=error.d.ts.map