import { NrpDltAgentDest } from '../dlt/index.js';
import { JWK, PoOPayload, PoRPayload } from '../types.js';
export declare function verifyPor(por: string, wallet: NrpDltAgentDest, connectionTimeout?: number): Promise<{
    porPayload: PoRPayload;
    pooPayload: PoOPayload;
    secretHex: string;
    destPublicJwk: JWK;
    origPublicJwk: JWK;
}>;
//# sourceMappingURL=verifyPor.d.ts.map