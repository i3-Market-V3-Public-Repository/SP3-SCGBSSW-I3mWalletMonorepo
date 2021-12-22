import { DisputeRequestPayload, JWK, PoOPayload, PoRPayload } from '../types';
import { WalletAgentDest } from '../dlt';
/**
 * Check if the cipherblock in the disputeRequest is the one agreed for the dataExchange, and if it could be decrypted with the secret published on the ledger for that dataExchange.
 *
 * @param disputeRequest a dispute request as a compact JWS
 * @param wallet
 * @returns
 */
export declare function checkDecryption(disputeRequest: string, wallet: WalletAgentDest): Promise<{
    drPayload: DisputeRequestPayload;
    porPayload: PoRPayload;
    pooPayload: PoOPayload;
    destPublicJwk: JWK;
    origPublicJwk: JWK;
}>;
//# sourceMappingURL=checkDecryption.d.ts.map