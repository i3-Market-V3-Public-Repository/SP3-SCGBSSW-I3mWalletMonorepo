import { NrpDltAgentDest } from '../dlt/index.js';
import { DisputeRequestPayload, JWK, PoOPayload, PoRPayload } from '../types.js';
export declare function checkDecryption(disputeRequest: string, wallet: NrpDltAgentDest): Promise<{
    drPayload: DisputeRequestPayload;
    porPayload: PoRPayload;
    pooPayload: PoOPayload;
    destPublicJwk: JWK;
    origPublicJwk: JWK;
}>;
//# sourceMappingURL=checkDecryption.d.ts.map