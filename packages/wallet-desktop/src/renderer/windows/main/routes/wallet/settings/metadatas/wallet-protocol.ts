import { DEFAULT_TOKEN_TLL } from '@wallet/lib'
import { MetadataRecord } from '../settings-metadata'

export const walletProtocolMetadata: MetadataRecord = {
  'Wallet Protocol': [
    {
      label: 'Enable Token expiration',
      type: 'checkbox',
      key: 'private.connect.enableTokenExpiration'
    },
    {
      label: 'Wallet protocol session TTL',
      type: 'number',
      placeholder: DEFAULT_TOKEN_TLL,
      key: 'private.connect.tokenTTL'
    }
  ]
}
