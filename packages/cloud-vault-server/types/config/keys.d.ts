import { OpenApiComponents } from '../../types/openapi';
export interface JwkPair {
    publicJwk: OpenApiComponents.Schemas.JwkEcPublicKey;
    privateJwk: OpenApiComponents.Schemas.JwkEcPublicKey & {
        d: string;
    };
}
export declare const jwksPromise: Promise<JwkPair>;
