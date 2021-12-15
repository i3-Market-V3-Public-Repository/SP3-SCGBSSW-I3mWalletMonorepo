import { Contract } from 'ethers';
import { JWK, PoOPayload, PoRPayload } from '../types';
export declare function verifyPor(por: string, dltContract: Contract): Promise<{
    porPayload: PoRPayload;
    pooPayload: PoOPayload;
    secretHex: string;
    destPublicJwk: JWK;
    origPublicJwk: JWK;
}>;
//# sourceMappingURL=verifyPor.d.ts.map