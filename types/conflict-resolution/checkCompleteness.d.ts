import { Contract } from 'ethers';
import { JWK, PoOPayload, PoRPayload, VerificationRequestPayload } from '../types';
/**
 * Checks the completeness of a given data exchange by verifying the PoR in the verification request using the secret downloaded from the ledger
 *
 * @param verificationRequest
 * @param dltContract
 * @returns
 */
export declare function checkCompleteness(verificationRequest: string, dltContract: Contract): Promise<{
    vrPayload: VerificationRequestPayload;
    porPayload: PoRPayload;
    pooPayload: PoOPayload;
    destPublicJwk: JWK;
    origPublicJwk: JWK;
}>;
//# sourceMappingURL=checkCompleteness.d.ts.map