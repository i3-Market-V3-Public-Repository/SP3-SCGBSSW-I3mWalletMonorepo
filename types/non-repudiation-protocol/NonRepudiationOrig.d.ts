import { ethers } from 'ethers';
import { DataExchange, DataExchangeAgreement, DltConfig, JWK, JwkPair, OrigBlock, PoOPayload, PoPPayload, PoRPayload, StoredProof, TimestampVerifyOptions } from '../types';
/**
 * The base class that should be instantiated by the origin of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Provider.
 */
export declare class NonRepudiationOrig {
    agreement: DataExchangeAgreement;
    exchange: DataExchange;
    jwkPairOrig: JwkPair;
    publicJwkDest: JWK;
    block: OrigBlock;
    dltConfig: Required<DltConfig>;
    dltContract: ethers.Contract;
    private readonly initialized;
    /**
     * @param agreement - a DataExchangeAgreement
     * @param privateJwk - the private key that will be used to sign the proofs
     * @param block - the block of data to transmit in this data exchange
     * @param dltConfig - an object with the necessary configuration for the (Ethereum-like) DLT
     * @param privateLedgerKeyHex - the private key (d parameter) as a hexadecimal string used to sign transactions to the ledger. If not provided, it is assumed that a DltSigner is provided in the dltConfig
     */
    constructor(agreement: DataExchangeAgreement, privateJwk: JWK, block: Uint8Array, dltConfig?: Partial<DltConfig>, privateLedgerKeyHex?: string);
    private init;
    private _dltSetup;
    /**
     * Creates the proof of origin (PoO).
     * Besides returning its value, it is also stored in this.block.poo
     *
     * @returns a compact JWS with the PoO along with its decoded payload
     */
    generatePoO(): Promise<StoredProof<PoOPayload>>;
    /**
     * Verifies a proof of reception.
     * If verification passes, `por` is added to `this.block`
     *
     * @param por - A PoR in caompact JWS format
     * @param options - time-related verifications
     * @returns the verified payload and protected header
     */
    verifyPoR(por: string, options?: Pick<TimestampVerifyOptions, 'timestamp' | 'tolerance'>): Promise<StoredProof<PoRPayload>>;
    /**
     * Creates the proof of publication (PoP).
     * Besides returning its value, it is also stored in `this.block.pop`
     *
     * @returns a compact JWS with the PoP
     */
    generatePoP(): Promise<StoredProof<PoPPayload>>;
    /**
     * Generates a verification request that can be used to query the
     * Conflict-Resolver Service for completeness of the non-repudiation protocol
     *
     * @returns the verification request as a compact JWS signed with 'orig's private key
     */
    generateVerificationRequest(): Promise<string>;
}
//# sourceMappingURL=NonRepudiationOrig.d.ts.map