import { JWK, JWTVerifyResult } from 'jose';
import { DataExchange, DataExchangeInit, JwkPair } from './types';
interface Block {
    raw: Uint8Array;
    jwe?: string;
    secret?: JWK;
    poo?: string;
    por?: string;
    pop?: string;
}
export declare class NonRepudiationOrig {
    dataExchange: DataExchangeInit;
    jwkPairOrig: JwkPair;
    publicJwkDest: JWK;
    block: Block;
    checked: boolean;
    constructor(dataExchangeId: DataExchange['id'], jwkPairOrig: JwkPair, publicJwkDest: JWK, block: Uint8Array, alg?: string);
    init(): Promise<void>;
    /**
     * Creates the proof of origin (PoO) as a compact JWS for the block of data. Besides returning its value, it is also stored in this.block.poo
     *
     */
    generatePoO(): Promise<string>;
    verifyPoR(por: string): Promise<JWTVerifyResult>;
    generatePoP(verificationCode: string): Promise<string>;
    private _checkInit;
}
export {};
//# sourceMappingURL=NonRepudiationOrig.d.ts.map