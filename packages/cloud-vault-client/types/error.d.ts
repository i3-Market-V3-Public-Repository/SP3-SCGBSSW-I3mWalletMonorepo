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
    'http-request-canceled': {
        request: {
            method?: string;
            url?: string;
            headers?: {
                [header: string]: string;
            };
            data?: any;
        };
    };
    'no-uploaded-storage': any;
    'sse-connection-error': any;
    'quota-exceeded': string;
    conflict: {
        localTimestamp?: number;
        remoteTimestamp?: number;
    };
    unauthorized: any;
    'invalid-credentials': any;
    error: Error;
    unknown: any;
    validation: {
        description?: string;
        data?: any;
    };
};
export type VaultErrorName = keyof VaultErrorData;
export type DataForError<T extends VaultErrorName> = VaultErrorData[T];
export declare class VaultError<T extends VaultErrorName = VaultErrorName> extends Error {
    data: any;
    message: T;
    constructor(message: T, data: DataForError<T>, options?: ErrorOptions);
    static from(error: unknown): VaultError;
}
export declare function checkErrorType<T extends VaultErrorName>(err: VaultError, type: T): err is VaultError<T>;
//# sourceMappingURL=error.d.ts.map