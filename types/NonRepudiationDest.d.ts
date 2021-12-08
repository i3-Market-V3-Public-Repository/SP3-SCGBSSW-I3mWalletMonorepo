import { ethers } from 'ethers';
import { Block, DataExchange, DataExchangeAgreement, DltConfig, JWK, JwkPair, JWTVerifyResult, StoredProof } from './types';
/**
 * The base class that should be instantiated by the destination of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Consumer.
 */
export declare class NonRepudiationDest {
    agreement: DataExchangeAgreement;
    exchange?: DataExchange;
    jwkPairDest: JwkPair;
    publicJwkOrig: JWK;
    block: Block;
    dltConfig: DltConfig;
    dltContract: ethers.Contract;
    initialized: Promise<boolean>;
    /**
     * @param agreement - a DataExchangeAgreement
     * @param privateJwk - the private key that will be used to sign the proofs
     * @param dltConfig - an object with the necessary configuration for the (Ethereum-like) DLT
     */
    constructor(agreement: DataExchangeAgreement, privateJwk: JWK, dltConfig?: Partial<DltConfig>);
    private _dltSetup;
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
     * @param clockToleranceMs - expected clock tolerance in milliseconds when comparing Dates
     * @param currentDate - check the PoO as it were checked in this date
     * @returns the verified payload and protected header
     *
     */
    verifyPoO(poo: string, cipherblock: string, clockToleranceMs?: number, currentDate?: Date): Promise<JWTVerifyResult>;
    /**
     * Creates the proof of reception (PoR).
     * Besides returning its value, it is also stored in `this.block.por`
     *
     * @returns the PoR as a compact JWS along with its decoded payload
     */
    generatePoR(): Promise<StoredProof>;
    /**
     * Verifies a received Proof of Publication (PoP) and returns the secret
     * @param pop - a PoP in compact JWS
     * @param clockToleranceMs - expected clock tolerance in milliseconds when comparing Dates
     * @param currentDate - check the proof as it were checked in this date
     * @returns the verified payload (that includes the secret that can be used to decrypt the cipherblock) and protected header
     */
    verifyPoP(pop: string, clockToleranceMs?: number, currentDate?: Date): Promise<JWTVerifyResult>;
    /**
     * Just in case the PoP is not received, the secret can be downloaded from the ledger.
     * The secret should be downloaded before poo.iat + pooTopop max delay.
     *
     * @returns the secret
     */
    getSecretFromLedger(): Promise<{
        hex: string;
        jwk: JWK;
    }>;
    /**
     * Decrypts the cipherblock once all the previous proofs have been verified
     * @returns the decrypted block
     *
     * @throws Error if the previous proofs have not been verified or the decrypted block does not meet the committed one
     */
    decrypt(): Promise<Uint8Array>;
}
//# sourceMappingURL=NonRepudiationDest.d.ts.map