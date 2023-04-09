import { NrpDltAgentDest } from '../dlt/index.js';
import { JWK, PoOPayload, PoRPayload, VerificationRequestPayload } from '../types.js';
export declare function checkCompleteness(verificationRequest: string, wallet: NrpDltAgentDest, connectionTimeout?: number): Promise<{
    vrPayload: VerificationRequestPayload;
    porPayload: PoRPayload;
    pooPayload: PoOPayload;
    destPublicJwk: JWK;
    origPublicJwk: JWK;
}>;
//# sourceMappingURL=checkCompleteness.d.ts.map