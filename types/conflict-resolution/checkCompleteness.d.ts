import { WalletAgentDest } from '..';
import { JWK, PoOPayload, PoRPayload, VerificationRequestPayload } from '../types';
/**
 * Checks the completeness of a given data exchange by verifying the PoR in the verification request using the secret downloaded from the ledger
 *
 * @param verificationRequest
 * @param wallet
 * @returns
 */
export declare function checkCompleteness(verificationRequest: string, wallet: WalletAgentDest, connectionTimeout?: number): Promise<{
    vrPayload: VerificationRequestPayload;
    porPayload: PoRPayload;
    pooPayload: PoOPayload;
    destPublicJwk: JWK;
    origPublicJwk: JWK;
}>;
//# sourceMappingURL=checkCompleteness.d.ts.map