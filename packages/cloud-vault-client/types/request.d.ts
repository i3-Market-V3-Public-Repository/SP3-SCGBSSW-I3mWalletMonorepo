import { AxiosInstance, AxiosResponse } from 'axios';
export interface RetryOptions {
    retries: number;
    retryDelay: number;
}
interface CallOptions {
    bearerToken?: string;
    responseStatus?: number;
    sequentialPost?: boolean;
}
export declare class Request {
    axios: AxiosInstance;
    defaultCallOptions?: CallOptions;
    defaultUrl?: string;
    private _stop;
    uploading: {
        [url: string]: Array<Promise<AxiosResponse>>;
    };
    constructor(opts?: {
        retryOptions?: RetryOptions;
        defaultCallOptions?: CallOptions;
        defaultUrl?: string;
    });
    private getAxiosInstance;
    waitForUploadsToFinsh(url?: string): Promise<void>;
    stop(): Promise<void>;
    get<T>(url: string, options?: CallOptions): Promise<T>;
    get<T>(options?: CallOptions): Promise<T>;
    delete<T>(url: string, options?: CallOptions): Promise<T>;
    delete<T>(options?: CallOptions): Promise<T>;
    private upload;
    post<T>(url: string, requestBody: any, options?: CallOptions): Promise<T>;
    post<T>(requestBody: any, options?: CallOptions): Promise<T>;
    put<T>(url: string, requestBody: any, options?: CallOptions): Promise<T>;
    put<T>(requestBody: any, options?: CallOptions): Promise<T>;
}
export {};
//# sourceMappingURL=request.d.ts.map