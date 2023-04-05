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
      key: 'private.connect.tokenTTL'
    }
  ]
}
