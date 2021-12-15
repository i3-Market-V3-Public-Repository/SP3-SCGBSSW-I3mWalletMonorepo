import { Contract } from 'ethers';
import { DisputeRequestPayload, JWK, PoOPayload, PoRPayload } from '../types';
/**
 * Check if the cipherblock in the disputeRequest is the one agreed for the dataExchange, and if it could be decrypted with the secret published on the ledger for that dataExchange.
 *
 * @param disputeRequest a dispute request as a compact JWS
 * @param dltContract
 * @returns
 */
export declare function checkDecryption(disputeRequest: string, dltContract: Contract): Promise<{
    drPayload: DisputeRequestPayload;
    porPayload: PoRPayload;
    pooPayload: PoOPayload;
    destPublicJwk: JWK;
    origPublicJwk: JWK;
}>;
//# sourceMappingURL=checkDecryption.d.ts.map