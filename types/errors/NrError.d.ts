import { NrErrorName } from '../types';
export declare class NrError extends Error {
    nrErrors: NrErrorName[];
    constructor(error: any, nrErrors: NrErrorName[]);
    add(...nrErrors: NrErrorName[]): void;
}
//# sourceMappingURL=NrError.d.ts.map