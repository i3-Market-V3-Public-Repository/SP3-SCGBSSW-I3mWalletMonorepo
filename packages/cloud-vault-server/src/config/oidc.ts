import { ClientMetadata } from 'openid-client'
import { parseProccessEnvVar } from './parseProcessEnvVar'
import { serverConfig } from './server'

interface OidcConfig {
  providerUri: string
  client: ClientMetadata
}

const clientId = parseProccessEnvVar('OIDC_CLIENT_ID', 'string')
const clientSecret = parseProccessEnvVar('OIDC_CLIENT_SECRET', 'string')
const providerUri = parseProccessEnvVar('OIDC_PROVIDER_URI', 'string')

export const oidcConfig: OidcConfig = {
  providerUri,
  client: {
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uris: [`${serverConfig.publicUrl}/api/v2/registration/cb`],
    application_type: 'web',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_jwt', // One of 'none' (only for PKCE), 'client_secret_basic', 'client_secret_jwt', 'client_secret_post', 'private_key_jwt'
    id_token_signed_response_alg: 'EdDSA' // One of 'HS256', 'PS256', 'RS256', 'ES256', 'EdDSA'
  }
}
