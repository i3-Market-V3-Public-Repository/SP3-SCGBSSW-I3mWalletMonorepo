import * as React from 'react'

import { Alert } from 'react-bootstrap'

import { DEFAULT_CLOUD_URL, DEFAULT_UPLOAD_DEBOUNCE_TIME, showToastAction } from '@wallet/lib'
import { MetadataRecord } from '../settings-metadata'

export const cloudVaultMetadata: MetadataRecord = {
  'Cloud Vault': [
    {
      type: 'info',
      description: {
        message: (
          <Alert variant='info'>
            Here I can put a message descriving what the cloud vault is and more bla bla things.
          </Alert>
        )
      }
    },
    {
      type: 'input',
      label: 'Cloud URL',
      key: 'public.cloud.url',
      placeholder: DEFAULT_CLOUD_URL,
      canUpdate (key, value, metadata, shm, dispatch) {
        const hasCredentials = shm.settings.private.cloud?.credentials !== undefined
        if (hasCredentials) {
          dispatch(showToastAction.create({
            message: 'Cannot update cloud URL',
            details: 'You are already logged in a secure cloud vault. Please logout to modify the vault URL.',
            type: 'warning'
          }))
          return false
        }

        return true
      }
    }
  ]
}

if (process.env.NODE_ENV === 'development') {
  cloudVaultMetadata['Cloud Vault'].push({
    type: 'input',
    label: 'Upload debounce time',
    key: 'private.cloud.uploadDebounceTime',
    placeholder: DEFAULT_UPLOAD_DEBOUNCE_TIME.toString()
  })
}
