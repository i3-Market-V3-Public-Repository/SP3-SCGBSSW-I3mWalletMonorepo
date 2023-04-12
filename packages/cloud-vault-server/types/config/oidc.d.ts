import { ClientMetadata } from 'openid-client';
interface OidcConfig {
    providerUri: string;
    client: ClientMetadata;
}
export declare const oidcConfig: OidcConfig;
export {};
