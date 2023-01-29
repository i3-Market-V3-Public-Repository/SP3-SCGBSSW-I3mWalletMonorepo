interface Options {
    defaultValue?: string | boolean;
    allowedValues?: string[];
    isBoolean?: boolean;
}
export declare function parseProccessEnvVar(varName: string, options?: Options): string | boolean;
export {};
