interface BooleanOptions {
    defaultValue: boolean;
}
interface StringOptions {
    defaultValue?: string;
    allowedValues?: string[];
}
export declare function parseProccessEnvVar(varName: string, type: 'string', options?: StringOptions): string;
export declare function parseProccessEnvVar(varName: string, type: 'boolean', options?: BooleanOptions): boolean;
export {};
