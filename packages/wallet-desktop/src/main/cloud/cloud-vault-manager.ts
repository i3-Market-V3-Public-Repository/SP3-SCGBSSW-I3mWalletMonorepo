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
    const { storeManager } = this.locals
    const privateSettings = storeManager.getStore('private-settings')
    const cloud = await privateSettings.get('cloud')

    const client = new VaultClient(CLOUD_URL, cloud?.token)
    client.on('connected', (t) => {

    })

    this._client = client
  }

  async getLoginData (errorMessage: string): Promise<LoginData> {
    const { dialog } = this.locals
    const loginData = await dialog.form<LoginData>({
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

  async registerUserTask (task: LabeledTaskHandler, loginData?: LoginData): Promise<void> {
    const { dialog } = this.locals
    const errorMessage = 'Vault user registration error'

    try {
      await this.client.initialized
    } catch (err: unknown) {
      if (err instanceof VaultError) {
        if (checkErrorType(err, 'not-initialized')) {
          throw new WalletDesktopError('Not initialized', {
            severity: 'error',
            message: errorMessage,
            details: 'Cannot connect to the vault server.'
          })
        }
        throw new WalletDesktopError('Something went wrong...')
      }
    }

    if (loginData === undefined) {
      loginData = await this.getLoginData(errorMessage)
    }

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

  async startVaultSyncTask (task: LabeledTaskHandler): Promise<void> {
    const { dialog, sharedMemoryManager } = this.locals
    const errorMessage = 'Vault synchronization error'

    try {
      await this.client.initialized
    } catch (err: unknown) {
      if (err instanceof VaultError) {
        if (checkErrorType(err, 'not-initialized') || checkErrorType(err, 'http-connection-error')) {
          throw new WalletDesktopError('No vault connection', {
            severity: 'error',
            message: errorMessage,
            details: 'Cannot connect to the vault server.'
          })
        }
        throw new WalletDesktopError('Something went wrong...')
      }
    }

    const confirm = await dialog.confirmation({
      title: 'Cloud Vault',
      message: 'Bla bla. Do you want to sync your wallet?',
      acceptMsg: 'Yes',
      rejectMsg: 'No'
    })
    if (confirm !== true) {
      return
    }

    const loginData = await this.getLoginData(errorMessage)

    try {
      await this.client.login(loginData.username, loginData.password)
      sharedMemoryManager.update(mem => ({
        ...mem,
        cloudVaultData: {
          state: 'in-progress'
        },
        settings: {
          ...mem.settings,
          cloud: {
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
            await this.registerUserTask(task, loginData)
            return
          }
        } else if (checkErrorType(err, 'not-initialized') || checkErrorType(err, 'http-connection-error')) {
          throw new WalletDesktopError('No vault connection', {
            severity: 'error',
            message: errorMessage,
            details: 'Cannot connect to the vault server.'
          })
        }
      }
      throw new WalletDesktopError('Something went wrong')
    }
  }

  async startVaultSync (): Promise<void> {
    const { taskManager } = this.locals
    const taskInfo: TaskDescription = { title: 'Vault Sync' }
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

  async registerUser (): Promise<void> {
    const { taskManager } = this.locals
    const taskInfo: TaskDescription = { title: 'Register Cloud User' }
    await taskManager.createTask('labeled', taskInfo, async (task) => {
      return await this.registerUserTask(task)
    })
  }

  async updateStorage (storage: Buffer, timestamp?: number): Promise<number> {
    return await this.client.updateStorage({
      storage: storage,
      timestamp
    })
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
