import { WalletAgentDest } from '../dlt';
import { JWK, PoOPayload, PoRPayload } from '../types';
export declare function verifyPor(por: string, wallet: WalletAgentDest, connectionTimeout?: number): Promise<{
    porPayload: PoRPayload;
    pooPayload: PoOPayload;
    secretHex: string;
    destPublicJwk: JWK;
    origPublicJwk: JWK;
}>;
//# sourceMappingURL=verifyPor.d.ts.map