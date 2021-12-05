import { JWK, JWTVerifyResult } from 'jose';
import { Algs, DataExchange, DataExchangeInit, DltConfig, JwkPair, OrigBlock } from './types';
/**
 * The base class that should be instantiated by the origin of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Provider.
 */
export declare class NonRepudiationOrig {
    exchange: DataExchangeInit;
    jwkPairOrig: JwkPair;
    publicJwkDest: JWK;
    block: OrigBlock;
    dltConfig: DltConfig;
    initialized: Promise<boolean>;
    /**
     * @param exchangeId - the id of this data exchange. It MUST be unique for the sender
     * @param jwkPairOrig - a pair of private and public keys owned by this entity (non-repudiation orig)
     * @param publicJwkDest - the public key as a JWK of the other peer (non-repudiation dest)
     * @param block - the block of data to transmit in this data exchange
     * @param dltConfig - an object with the necessary configuration for the (Ethereum-like) DLT
     * @param algs - is used to overwrite the default algorithms for hash (SHA-256), signing (ES256) and encryption (A256GCM)
     */
    constructor(exchangeId: DataExchange['id'], jwkPairOrig: JwkPair, publicJwkDest: JWK, block: Uint8Array, dltConfig?: Partial<DltConfig>, algs?: Algs);
    /**
     * Initialize this instance. It MUST be invoked before calling any other method.
     */
    init(): Promise<void>;
    private _dltSetup;
    /**
     * Creates the proof of origin (PoO).
     * Besides returning its value, it is also stored in this.block.poo
     *
     * @returns a compact JWS with the PoO
     */
    generatePoO(): Promise<string>;
    /**
     * Verifies a proof of reception.
     * If verification passes, `por` is added to `this.block`
     *
     * @param por - A PoR in caompact JWS format
     * @returns the verified payload and protected header
     */
    verifyPoR(por: string): Promise<JWTVerifyResult>;
    /**
     * Creates the proof of publication (PoP).
     * Besides returning its value, it is also stored in `this.block.pop`
     *
     * @returns a compact JWS with the PoP
     */
    generatePoP(): Promise<string>;
}
//# sourceMappingURL=NonRepudiationOrig.d.ts.map