import { JWK, JWTVerifyResult } from 'jose';
import { DataExchange, DataExchangeInit, JwkPair } from './types';
interface Block {
    jwe: string;
    decrypted?: Uint8Array;
    secret?: JWK;
    poo?: string;
    por?: string;
    pop?: string;
}
export declare class NonRepudiationDest {
    dataExchange: DataExchangeInit;
    jwkPairDest: JwkPair;
    publicJwkOrig: JWK;
    block?: Block;
    checked: boolean;
    constructor(dataExchangeId: DataExchange['id'], jwkPairDest: JwkPair, publicJwkOrig: JWK);
    init(): Promise<void>;
    verifyPoO(poo: string, cipherblock: string): Promise<JWTVerifyResult>;
    /**
     * Creates the proof of reception (PoR) as a compact JWS for the block of data. Besides returning its value, it is also stored in this.block.por
     *
     */
    generatePoR(): Promise<string>;
    verifyPoPAndDecrypt(pop: string, secret: string, verificationCode: string): Promise<{
        verified: JWTVerifyResult;
        decryptedBlock: Uint8Array;
    }>;
    private _checkInit;
}
export {};
//# sourceMappingURL=NonRepudiationDest.d.ts.map