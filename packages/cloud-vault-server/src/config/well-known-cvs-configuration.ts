import { OpenApiComponents } from '../../types/openapi'
import { dbConfig } from './db'
import { apiVersion } from './openApi'
import { parseProccessEnvVar } from './parseProcessEnvVar'

const id = parseProccessEnvVar('SERVER_ID', 'string')

export const wellKnownCvsConfiguration: OpenApiComponents.Schemas.CvsConfiguration = {
  name: '',
  registration_configuration: {
    public_jwk_endpoint: `/api/${apiVersion}/registration/public-jwk`,
    registration_endpoint: `/api/${apiVersion}/registration/register/{data}`,
    deregistration_endpoint: `/api/${apiVersion}/registration/deregister`
  },
  vault_configuration: {
    v2: {
      id,
      version: 'v2',
      vault_size: dbConfig.storageByteLength,
      vault_endpoint: '/api/v2/vault',
      events_endpoint: '/api/v2/vault/events',
      timestamp_endpoint: '/api/v2/vault/timestamp',
      token_endpoint: '/api/v2/vault/token',
      token_endpoint_auth_methods_supported: [
        'client_secret_post'
      ],
      key_derivation: {
        master: {
          alg: 'scrypt',
          derived_key_length: 32,
          input: 'password',
          salt_pattern: 'master' + id + '{username}',
          salt_hashing_algorithm: 'sha512',
          alg_options: {
            N: 2 ** 19,
            p: 2,
            r: 8
          }
        },
        auth: {
          alg: 'scrypt',
          derived_key_length: 32,
          input: 'master-key',
          salt_pattern: 'auth' + id + '{username}',
          salt_hashing_algorithm: 'sha512',
          alg_options: {
            N: 2 ** 16,
            p: 1,
            r: 8
          }
        },
        enc: {
          alg: 'scrypt',
          derived_key_length: 32,
          input: 'master-key',
          salt_pattern: 'enc' + id + '{username}',
          salt_hashing_algorithm: 'sha512',
          alg_options: {
            N: 2 ** 16,
            p: 1,
            r: 8
          },
          enc_algorithm: 'aes-256-gcm'
        }
      }
    }
  }
}
