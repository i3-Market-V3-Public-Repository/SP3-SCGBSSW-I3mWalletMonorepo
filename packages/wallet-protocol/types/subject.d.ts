export declare class Subject<T = unknown> {
    protected resolve?: (value: T) => void;
    protected reject?: (reason: any) => void;
    get promise(): Promise<T>;
    protected createPromise(): Promise<T>;
    next(value: T): void;
    err(reason: any): void;
}
//# sourceMappingURL=subject.d.ts.map