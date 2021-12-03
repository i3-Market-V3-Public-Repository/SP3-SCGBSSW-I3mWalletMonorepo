import { JWK, JWTVerifyResult } from 'jose';
import { DataExchange, DataExchangeInit, DestBlock, JwkPair } from './types';
/**
 * The base class that should be instantiated by the destination of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Consumer.
 */
export declare class NonRepudiationDest {
    exchange: DataExchangeInit;
    jwkPairDest: JwkPair;
    publicJwkOrig: JWK;
    block?: DestBlock;
    checked: boolean;
    /**
     *
     * @param exchangeId - the id of this data exchange. It MUST be unique for the same origin and destination
     * @param jwkPairDest - a pair of private and public keys owned by this entity (non-repudiation dest)
     * @param publicJwkOrig - the public key as a JWK of the other peer (non-repudiation orig)
     */
    constructor(exchangeId: DataExchange['id'], jwkPairDest: JwkPair, publicJwkOrig: JWK);
    /**
     * Initialize this instance. It MUST be invoked before calling any other method.
     */
    init(): Promise<void>;
    /**
     * Verifies a proof of origin against the received cipherblock.
     * If verification passes, `pop` and `cipherblock` are added to this.block
     *
     * @param poo - a Proof of Origin (PoO) in compact JWS format
     * @param cipherblock - a cipherblock as a JWE
     * @returns the verified payload and protected header
     *
     */
    verifyPoO(poo: string, cipherblock: string): Promise<JWTVerifyResult>;
    /**
     * Creates the proof of reception (PoR).
     * Besides returning its value, it is also stored in `this.block.por`
     *
     * @returns a compact JWS with the PoR
     */
    generatePoR(): Promise<string>;
    /**
     * Verifies a received Proof of Publication (PoP) with the received secret and verificationCode
     * @param pop - a PoP in compact JWS
     * @param secret - the JWK secret that was used to encrypt the block
     * @param verificationCode - the verification code
     * @returns the verified payload and protected header
     */
    verifyPoP(pop: string, secret: JWK): Promise<JWTVerifyResult>;
    /**
     * Decrypts the cipherblock once all the previous proofs have been verified
     * @returns the decrypted block
     *
     * @throws Error if the previous proofs have not been verified or the decrypted block does not meet the committed one
     */
    decrypt(): Promise<Uint8Array>;
    private _checkInit;
}
//# sourceMappingURL=NonRepudiationDest.d.ts.map