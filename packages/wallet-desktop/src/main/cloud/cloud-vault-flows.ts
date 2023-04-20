import { VerifiableCredentialResource } from "@i3m/base-wallet"
import { Credentials } from "@wallet/lib"

import { Locals, WalletDesktopError } from '@wallet/main/internal'

export class CloudVaultFlows {
  constructor(protected locals: Locals) {}

  async getCloudVaultUrl (): Promise<string> {
    const { storeManager, dialog } = this.locals
    const publicSettings = storeManager.getStore('public-settings')
    let cloud = await publicSettings.get('cloud')

    if (cloud?.url === undefined) {
      const vaultUrl = await dialog.text({
        title: 'Cloud Vault',
        message: 'You must provide the URL of your Cloud Vault server (i.e. https://my-vault-server.com:8000)',
        allowCancel: true
      })
      if (vaultUrl !== undefined) {
        cloud = {
          unsyncedChanges: false,
          ...cloud,
          url: vaultUrl
        }
        await publicSettings.set('cloud', cloud)
      }
    }

    const url = cloud?.url
    if (url === undefined) {
      throw new WalletDesktopError('Invalid URL for the Cloud Vault server', {
        message: 'Cloud Vault',
        details: 'Invalid URL for the Cloud Vault server'
      })
    }

    return url
  }

  async getCredentials (errorMessage: string): Promise<Credentials> {
    const { dialog } = this.locals
    const loginData = await dialog.form<Credentials>({
      title: 'Cloud Vault',
      descriptors: {
        username: { type: 'text', message: 'Introduce your username' },
        password: { type: 'text', message: 'Introduce your password', hiddenText: true }
      },
      order: ['username', 'password']
    })
    if (loginData === undefined) {
      throw new WalletDesktopError('You need to provide a valid username and password.', {
        severity: 'error',
        message: errorMessage,
        details: 'You need to provide a valid username and password.'
      })
    }
    return loginData
  }

  async confirmPassword (credential: Credentials): Promise<void> {
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

  async getRegistrationCredential (errorMessage: string): Promise<VerifiableCredentialResource> {
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
