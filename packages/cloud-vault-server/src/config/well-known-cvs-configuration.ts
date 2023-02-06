import { OpenApiComponents } from '../../types/openapi'
import { apiVersion } from './openApi'
import { parseProccessEnvVar } from './parseProcessEnvVar'

const id = parseProccessEnvVar('SERVER_ID', 'string')

export const wellKnownCvsConfiguration: OpenApiComponents.Schemas.CvsConfiguration = {
  name: '',
  'registration-configuration': {
    'public-jwk_endpoint': `/api/${apiVersion}/registration/public-jwk`,
    registration_endpoint: `/api/${apiVersion}/registration/{data}`
  },
  'vault-configuration': {
    v2: {
      id,
      version: 'v2',
      vault_endpoint: '/api/v2/vault',
      events_endpoint: '/api/v2/vault/events',
      timestamp_endpoint: 'api/v2/vault/timestamp',
      token_endpoint: '/api/v2/vault/token',
      token_endpoint_auth_methods_supported: [
        'client_secret_post'
      ],
      'key-derivation': {
        master: {
          alg: 'scrypt',
          derivedKeyLength: 32,
          input: 'password',
          saltPattern: 'master' + id + '{username}',
          saltHashingAlgorithm: 'sha3-512',
          algOptions: {
            N: 2 ** 22,
            p: 1,
            r: 8
          }
        },
        auth: {
          alg: 'scrypt',
          derivedKeyLength: 32,
          input: 'master-key',
          saltPattern: 'auth' + id + '{username}',
          saltHashingAlgorithm: 'sha3-512',
          algOptions: {
            N: 2 ** 16,
            p: 1,
            r: 8
          }
        },
        enc: {
          alg: 'scrypt',
          derivedKeyLength: 32,
          input: 'master-key',
          saltPattern: 'enc' + id + '{username}',
          saltHashingAlgorithm: 'sha3-512',
          algOptions: {
            N: 2 ** 16,
            p: 1,
            r: 8
          }
        }
      }
    }
  }
}
