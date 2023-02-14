import { VerifiableCredentialResource } from '@i3m/base-wallet'
import { checkErrorType, VaultClient, VaultError } from '@i3m/cloud-vault-client'
import { jweEncrypt, JWK } from '@i3m/non-repudiation-library'
import { shell } from 'electron'

import { TaskDescription } from '@wallet/lib'
import { LabeledTaskHandler, Locals, WalletDesktopError } from '@wallet/main/internal'

interface LoginData {
  username: string
  password: string
}

const CLOUD_URL = 'http://localhost:3000'

export class CloudVaultManager {
  _client?: VaultClient
  constructor (protected locals: Locals) { }

  async initialize (): Promise<void> {
    const { settings } = this.locals
    const cloud = await settings.get('cloud')

    const client = new VaultClient(CLOUD_URL, cloud?.token)
    client.on('connected', (t) => {

    })
    this._client = client
  }

  async startVaultSyncTask (task: LabeledTaskHandler): Promise<void> {
    const errorMessage = 'Vault synchronization error'
    const { dialog, sharedMemoryManager } = this.locals
    const confirm = await dialog.confirmation({
      title: 'Cloud Vault',
      message: 'Bla bla. Do you want to sync your wallet?',
      acceptMsg: 'Yes',
      rejectMsg: 'No'
    })
    if (confirm !== true) {
      return
    }

    const loginData = await dialog.form<LoginData>({
      title: 'Cloud Vault',
      descriptors: {
        username: { type: 'text', message: 'Introduce your username' },
        password: { type: 'text', message: 'Introduce your password', hiddenText: true }
      },
      order: ['username', 'password']
    })
    if (loginData === undefined) {
      throw new WalletDesktopError('You need to provide a valid username and password to start the wallet synchronization.', {
        severity: 'error',
        message: errorMessage,
        details: 'You need to provide a valid username and password to start the wallet synchronization.'
      })
    }

    try {
      await this.client.login(loginData.username, loginData.password)
      sharedMemoryManager.update(mem => ({
        ...mem,
        settings: {
          ...mem.settings,
          cloud: {
            state: 'in-progress',
            token: this.client.token as string
          }
        }
      }))
    } catch (err) {
      if (err instanceof VaultError) {
        if (checkErrorType(err, 'invalid-credentials')) {
          const confirm = await dialog.confirmation({
            title: 'Cloud Vault',
            message: 'Invalid credentials. Do you want to proceed with the registration of this credentials?',
            acceptMsg: 'Yes',
            rejectMsg: 'No'
          })
          if (confirm === true) {
            await this.registerUser(loginData, task)
            return
          }
        }
      }
      throw err
    }
  }

  async startVaultSync (): Promise<void> {
    const { taskManager } = this.locals
    const taskInfo: TaskDescription = {
      title: 'Vault Sync'
    }
    await taskManager.createTask('labeled', taskInfo, async (task) => {
      return await this.startVaultSyncTask(task)
    })
  }

  async stopVaultSync (): Promise<void> {
    const { dialog } = this.locals
    const confirm = await dialog.confirmation({
      title: 'Cloud Vault',
      message: 'Do you want to stop the cloud vault synchronization?',
      acceptMsg: 'Yes',
      rejectMsg: 'No'
    })
    if (confirm !== true) {
      return
    }

    this.client.logout()
    this.locals.sharedMemoryManager.update(mem => ({
      ...mem,
      settings: {
        ...mem.settings,
        cloud: undefined
      }
    }))
  }

  async registerUser (loginData: LoginData, task: LabeledTaskHandler) {
    const { dialog } = this.locals
    const errorMessage = 'Vault user registration error'

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

    const publicJwk = await this.client.getServerPublicKey()
    const data = await jweEncrypt(
      Buffer.from(JSON.stringify({
        did: vc.identity,
        username: loginData.username,
        authkey: await VaultClient.computeAuthKey(CLOUD_URL, loginData.username, loginData.password)
      })),
      publicJwk as JWK,
      'A256GCM'
    )

    const res = `${CLOUD_URL}${this.client.wellKnownCvsConfiguration?.registration_configuration.registration_endpoint.replace('{data}', data) ?? ''}`
    await shell.openExternal(res)
  }

  get client (): VaultClient {
    if (this._client === undefined) {
      throw new WalletDesktopError('The vault client is not initialized', {
        critical: false
      })
    }
    return this._client
  }
}
