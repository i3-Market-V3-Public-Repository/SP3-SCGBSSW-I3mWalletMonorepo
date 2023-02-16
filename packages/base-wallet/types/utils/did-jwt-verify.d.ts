import { Veramo } from '../veramo';
import { WalletPaths } from '@i3m/wallet-desktop-openapi/types';
/**
   * Verifies a JWT resolving the public key from the signer DID (no other kind of signer supported) and optionally check values for expected payload claims.
   *
   * The Wallet only supports the 'ES256K1' algorithm.
   *
   * Useful to verify JWT created by another wallet instance.
   * @param requestBody
   * @returns
   */
export declare function didJwtVerify(jwt: string, veramo: Veramo, expectedPayloadClaims?: any): Promise<WalletPaths.DidJwtVerify.Responses.$200>;
//# sourceMappingURL=did-jwt-verify.d.ts.map