import { ethers } from 'ethers';
import { DltConfig, JwkPair } from '../types';
/**
 * The base class that should be instantiated in order to create a Conflict Resolver instance.
 * The Conflict Resolver is an external entity that can:
 *  1. verify the completeness of a data exchange that used the non-repudiation protocol;
 *  2. resolve a dispute when a consumer states that she/he cannot decrypt the data received
 */
export declare class ConflictResolver {
    jwkPair: JwkPair;
    dltConfig: DltConfig;
    dltContract: ethers.Contract;
    private readonly initialized;
    /**
     *
     * @param jwkPair a pair of public/private keys in JWK format
     * @param dltConfig
     */
    constructor(jwkPair: JwkPair, dltConfig?: Partial<DltConfig>);
    private _dltSetup;
    /**
     * Initialize this instance.
     */
    private init;
    /**
     * Checks if a give data exchange has completed succesfully
     *
     * @param verificationRequest
     * @returns a signed resolution
     */
    resolveCompleteness(verificationRequest: string): Promise<string>;
    /**
     * Checks if the cipherblock provided in a data exchange can be decrypted
     * with the published secret.
     *
     * @todo Check also data schema
     *
     * @param disputeRequest
     * @returns a signed resolution
     */
    resolveDispute(disputeRequest: string): Promise<string>;
    private _resolution;
}
//# sourceMappingURL=ConflictResolver.d.ts.map