import type { OpenApiComponents } from '../../types/openapi'
import { dbConfig } from './db'
import { apiVersion } from './openApi'
import { serverConfig } from './server'

export const wellKnownCvsConfiguration: OpenApiComponents.Schemas.CvsConfiguration = {
  name: serverConfig.id,
  registration_configuration: {
    public_jwk_endpoint: `${serverConfig.publicUrl}/api/${apiVersion}/registration/public-jwk`,
    registration_endpoint: `${serverConfig.publicUrl}/api/${apiVersion}/registration/register/{data}`,
    deregistration_endpoint: `${serverConfig.publicUrl}/api/${apiVersion}/registration/deregister`
  },
  vault_configuration: {
    v2: {
      id: serverConfig.id,
      version: 'v2',
      vault_size: dbConfig.storageByteLength,
      vault_endpoint: `${serverConfig.publicUrl}/api/v2/vault`,
      events_endpoint: `${serverConfig.publicUrl}/api/v2/vault/events`,
      timestamp_endpoint: `${serverConfig.publicUrl}/api/v2/vault/timestamp`,
      token_endpoint: `${serverConfig.publicUrl}/api/v2/vault/token`,
      token_endpoint_auth_methods_supported: [
        'client_secret_post'
      ],
      key_derivation: {
        master: {
          alg: 'scrypt',
          derived_key_length: 32,
          input: 'password',
          salt_pattern: 'master' + serverConfig.id + '{username}',
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
          salt_pattern: 'auth' + serverConfig.id + '{username}',
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
          salt_pattern: 'enc' + serverConfig.id + '{username}',
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
