export interface MultipleExecutionsOptions {
    successRate?: number;
    timeout?: number;
}
export declare function multipleExecutions<T extends any>(options: MultipleExecutionsOptions, executors: any[], fnName: string, ...args: any[]): Promise<T[]>;
//# sourceMappingURL=multiple-executions.d.ts.map