import { DisputeRequestPayload, JWK, PoOPayload, PoRPayload } from '../types';
import { NrpDltAgentDest } from '../dlt';
export declare function checkDecryption(disputeRequest: string, wallet: NrpDltAgentDest): Promise<{
    drPayload: DisputeRequestPayload;
    porPayload: PoRPayload;
    pooPayload: PoOPayload;
    destPublicJwk: JWK;
    origPublicJwk: JWK;
}>;
//# sourceMappingURL=checkDecryption.d.ts.map