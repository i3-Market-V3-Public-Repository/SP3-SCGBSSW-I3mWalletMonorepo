import { NrpDltAgentDest } from '../dlt/agents/index.js';
import { JwkPair } from '../types.js';
export declare class ConflictResolver {
    jwkPair: JwkPair;
    dltAgent: NrpDltAgentDest;
    private readonly initialized;
    constructor(jwkPair: JwkPair, dltAgent: NrpDltAgentDest);
    private init;
    resolveCompleteness(verificationRequest: string): Promise<string>;
    resolveDispute(disputeRequest: string): Promise<string>;
    private _resolution;
}
//# sourceMappingURL=ConflictResolver.d.ts.map