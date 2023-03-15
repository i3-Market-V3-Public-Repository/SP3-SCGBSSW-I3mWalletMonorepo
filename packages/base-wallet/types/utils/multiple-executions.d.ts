export interface MultipleExecutionsOptions {
    successRate?: number;
    timeout?: number;
}
type FunctionMap<K extends string> = {
    [P in K]: (...args: any) => any;
};
type ValueOrResolvedValue<T> = T extends Promise<infer R> ? R : T;
export type MultipleExecutionsReturn<K extends string, T extends FunctionMap<K>> = ValueOrResolvedValue<ReturnType<T[K]>>;
export declare function multipleExecutions<K extends string, T extends FunctionMap<K>>(options: MultipleExecutionsOptions, executors: T[], fnName: K, ...args: any[]): Promise<Array<MultipleExecutionsReturn<K, T>>>;
export {};
//# sourceMappingURL=multiple-executions.d.ts.map