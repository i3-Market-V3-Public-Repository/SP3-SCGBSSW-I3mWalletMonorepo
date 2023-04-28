import { VerifiableCredentialResource } from '@i3m/base-wallet'
import { passwordCheck } from '@i3m/cloud-vault-client'
import { Credentials, DEFAULT_CLOUD_URL, DEFAULT_VAULT_PROVIDERS, filled } from '@wallet/lib'

import { getVersionDate, Locals, WalletDesktopError } from '@wallet/main/internal'
import { SyncDirection } from './sync-manager'

export class CloudVaultFlows {
  constructor (protected locals: Locals) {}

  async askConflictResolution (localTimestamp?: number, remoteTimestamp?: number): Promise<SyncDirection> {
    const { dialog } = this.locals

    const optionBuilder = dialog.useOptionsBuilder()
    const remote = optionBuilder.add('Remote version')
    const local = optionBuilder.add('Local version')
    optionBuilder.add('Cancel', 'danger')

    const localVersion = getVersionDate(localTimestamp)
    const remoteVersion = getVersionDate(remoteTimestamp)

    const response = await dialog.select({
      title: 'Cloud Vault',
      message: `There has been a conflict between the local version (${localVersion}) and the remote version ('${remoteVersion}).\n\n Which version would you want to use?`,
      allowCancel: true,
      ...optionBuilder
    })

    if (optionBuilder.compare(remote, response)) {
      return 'pull'
    } else if (optionBuilder.compare(local, response)) {
      return 'push'
    }

    return 'none'
  }

  async askCloudVaultUrl (): Promise<string> {
    const { storeManager, sharedMemoryManager: shm, dialog } = this.locals
    const cloud = shm.memory.settings.public.cloud
    let url = cloud?.url

    if (!filled(url)) {
      const vaultUrl = await dialog.select({
        title: 'Cloud Vault',
        message: `You must provide the URL of your Cloud Vault server (i.e. ${DEFAULT_CLOUD_URL})`,
        allowCancel: true,
        values: DEFAULT_VAULT_PROVIDERS
      })

      if (vaultUrl !== undefined) {
        url = vaultUrl
        await storeManager.silentStoreVaultUrl(vaultUrl)
      }
    }

    if (url === undefined) {
      throw new WalletDesktopError('Invalid URL for the Cloud Vault server', {
        message: 'Cloud Vault',
        details: 'Invalid URL for the Cloud Vault server'
      })
    }

    return url
  }

  async askCredentials (errorMessage: string, opts?: { credentials?: Credentials, store?: boolean}): Promise<Credentials> {
    const { dialog, sharedMemoryManager: shm, storeManager } = this.locals
    let credentials = opts?.credentials
    const storeCredentials = opts?.store ?? false

    if (credentials !== undefined) {
      return credentials
    }

    const cloud = shm.memory.settings.private.cloud
    if (cloud?.credentials !== undefined) {
      return cloud.credentials
    }

    credentials = await dialog.form<Credentials>({
      title: 'Cloud Vault',
      descriptors: {
        username: { type: 'text', message: 'Introduce your username' },
        password: { type: 'text', message: 'Introduce your password', hiddenText: true }
      },
      order: ['username', 'password']
    })
    if (credentials === undefined) {
      throw new WalletDesktopError('You need to provide a valid username and password.', {
        severity: 'error',
        message: errorMessage,
        details: 'You need to provide a valid username and password.'
      })
    }

    passwordCheck(credentials.password)
    if (storeCredentials) {
      await storeManager.silentStoreCredentials(credentials)
    }

    return credentials
  }

  async askPasswordConfirmation (credential: Credentials): Promise<void> {
    const { dialog } = this.locals
    const totalTries = 3
    let triesLeft = totalTries
    while (triesLeft > 0) {
      const password = await dialog.text({
        message: `Confirm the password (${triesLeft}/${totalTries} tries left).`,
        hiddenText: true
      })

      if (password === credential.password) {
        return
      }
      triesLeft--
    }

    throw new WalletDesktopError('Confirmation password does not match', {
      severity: 'warning',
      message: 'Cloud Vault Registration',
      details: 'Confirmation password does not match'
    })
  }

  async askRegistrationCredential (errorMessage: string): Promise<VerifiableCredentialResource> {
    const { dialog } = this.locals

    const resources = Object.values(this.locals.sharedMemoryManager.memory.resources)
    const vcs = resources.filter((resource) => {
      if (resource?.type !== 'VerifiableCredential') return false

      const subject = resource.resource.credentialSubject
      if (subject.consumer === true || subject.provider === true) {
        return true
      }
      return false
    }) as VerifiableCredentialResource[]

    let vc: VerifiableCredentialResource | undefined
    if (vcs.length > 1) {
      const response = await dialog.select({
        title: 'Cloud Vault',
        message: 'Select a valid i3-market identity to register it into the vault server.',
        values: vcs,
        getText (vc) {
          const subject = vc.resource.credentialSubject
          const type = subject.consumer === undefined ? 'Provider' : 'Consumer'

          return `${type} (${vc.resource.credentialSubject.id.substring(0, 23)}...)`
        }
      })

      vc = response
    } else {
      vc = vcs[0]
    }

    if (vc === undefined) {
      throw new WalletDesktopError('You need a valid provider/consumer i3-market credential to register a user', {
        severity: 'error',
        message: errorMessage,
        details: 'You need a valid provider/consumer i3-market credential to register a user'
      })
    }

    return vc
  }
}
