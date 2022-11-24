
import { ExternalLink } from '@wallet/renderer/components'
import { SettingsMetadataRecord } from '../settings-metadata'

export const developerMetadata: SettingsMetadataRecord = {
  Developer: [
    {
      label: 'Developer Functions',
      type: 'checkbox',
      key: 'developer.enableDeveloperFunctions'
    },
    {
      label: 'Developer API',
      type: 'checkbox',
      key: 'developer.enableDeveloperApi',
      description: {
        visible: (metadata, value) => value,
        message: (
          <ul>
            <li>OpenAPI Specification: <ExternalLink href='http://localhost:29170' /></li>
            <li>Pairing tests: <ExternalLink href='http://localhost:29170/pairing' /></li>
          </ul>
        )
      }
    }
  ]
}
