import { NrpDltAgentDest } from '../dlt/agents';
import { JwkPair } from '../types';
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