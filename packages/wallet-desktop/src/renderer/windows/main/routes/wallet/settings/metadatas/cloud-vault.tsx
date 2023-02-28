
import { DEFAULT_CLOUD_URL, showToastAction } from '@wallet/lib'
import { MetadataRecord } from '../settings-metadata'

export const cloudVaultMetadata: MetadataRecord = {
  'Cloud Vault': [
    {
      type: 'info',
      description: {
        message: <div>Here I can put a message descriving what the cloud vault is and more bla bla things.</div>
      }
    },
    {
      type: 'input',
      label: 'Cloud URL',
      key: 'cloud.url',
      placeholder: DEFAULT_CLOUD_URL,
      canUpdate (key, value, metadata, shm, dispatch) {
        const hasCredentials = shm.settings.cloud?.credentials !== undefined
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
