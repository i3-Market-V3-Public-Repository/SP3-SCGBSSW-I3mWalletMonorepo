import { NrpDltAgentDest } from '../dlt/agents';
import { JwkPair } from '../types';
/**
 * The base class that should be instantiated in order to create a Conflict Resolver instance.
 * The Conflict Resolver is an external entity that can:
 *  1. verify the completeness of a data exchange that used the non-repudiation protocol;
 *  2. resolve a dispute when a consumer states that she/he cannot decrypt the data received
 */
export declare class ConflictResolver {
    jwkPair: JwkPair;
    dltAgent: NrpDltAgentDest;
    private readonly initialized;
    /**
     *
     * @param jwkPair a pair of public/private keys in JWK format
     * @param dltAgent a DLT agent providing read-only access to the non-repudiation protocol smart contract
     */
    constructor(jwkPair: JwkPair, dltAgent: NrpDltAgentDest);
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