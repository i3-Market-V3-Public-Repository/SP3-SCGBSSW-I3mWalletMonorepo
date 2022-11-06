export declare const bufferUtils: {
    join: (...list: Uint8Array[]) => Uint8Array;
    split: (buffer: Uint8Array, ...sizes: number[]) => Uint8Array[];
    insertBytes: (src: Uint8Array, dst: Uint8Array, fromStart: number, toStart: number, size: number) => void;
    insertBits: (src: Uint8Array, dst: Uint8Array, fromStart: number, toStart: number, size: number) => void;
    extractBits: (buf: Uint8Array, start: number, size: number) => Uint8Array;
};
//# sourceMappingURL=buffer.d.ts.map