import { MetadataRecord } from '../settings-metadata'

export const walletProtocolMetadata: MetadataRecord = {
  'Wallet Protocol': [
    {
      label: 'Enable Token expiration',
      type: 'checkbox',
      key: 'connect.enableTokenExpiration'
    },
    {
      label: 'Wallet protocol session TTL',
      type: 'number',
      key: 'connect.tokenTTL'
    }
  ]
}
