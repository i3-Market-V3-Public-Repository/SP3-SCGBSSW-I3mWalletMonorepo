export declare class ConnectionString {
    protected buffer: Uint8Array;
    protected l: number;
    constructor(buffer: Uint8Array, l: number);
    toString(): string;
    extractPort(): number;
    extractRb(): Uint8Array;
    static generate(port: number, l: number): Promise<ConnectionString>;
    static fromString(connString: string, l: number): ConnectionString;
}
//# sourceMappingURL=connection-string.d.ts.map