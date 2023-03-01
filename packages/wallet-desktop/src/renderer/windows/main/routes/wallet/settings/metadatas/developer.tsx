import * as React from 'react'

import { Alert } from 'react-bootstrap'

import { Bootstrap, ExternalLink } from '@wallet/renderer/components'
import { MetadataRecord } from '../settings-metadata'

export const developerMetadata: MetadataRecord = {
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
          <Bootstrap>
            <Alert variant='light'>
              <ul>
                <li>OpenAPI Specification: <ExternalLink href='http://localhost:29170' /></li>
                <li>Pairing tests: <ExternalLink href='http://localhost:29170/pairing' /></li>
              </ul>
            </Alert>
          </Bootstrap>
        )
      }
    }
  ]
}
