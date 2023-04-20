import * as React from 'react'

import { Alert } from 'react-bootstrap'

import { InternalLink } from '@wallet/renderer/components'
import { MetadataRecord } from '../settings-metadata'

export const developerMetadata: MetadataRecord = {
  Developer: [
    {
      label: 'Developer Functions',
      type: 'checkbox',
      key: 'private.developer.enableDeveloperFunctions'
    },
    {
      label: 'Developer API',
      type: 'checkbox',
      key: 'private.developer.enableDeveloperApi',
      description: {
        visible: (metadata, value) => value,
        message: (
          <Alert variant='info'>
            <ul>
              <li>OpenAPI Specification: <InternalLink href='http://localhost:29170' /></li>
              <li>Pairing tests: <InternalLink href='http://localhost:29170/pairing' /></li>
            </ul>
          </Alert>
        )
      }
    }
  ]
}
