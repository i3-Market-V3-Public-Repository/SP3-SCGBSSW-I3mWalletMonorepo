import { DialogOptionContext, VerifiableCredentialResource } from '@i3m/base-wallet'
import { checkErrorType, VaultClient, VaultError } from '@i3m/cloud-vault-client'
import { jweEncrypt, JWK } from '@i3m/non-repudiation-library'
import { shell } from 'electron'

import { CloudVaultSettings, TaskDescription } from '@wallet/lib'
import { handleErrorCatch, handlePromise, LabeledTaskHandler, Locals, MainContext, WalletDesktopError } from '@wallet/main/internal'

const CLOUD_URL = 'http://localhost:3000'

interface DialogOption {
  id: number
  text: string
  context: DialogOptionContext
}

export class CloudVaultManager {
  // Static initialization
  static async initialize (ctx: MainContext, locals: Locals): Promise<CloudVaultManager> {
    return new CloudVaultManager(ctx, locals, {})
  }

  client: VaultClient
  failed: boolean
  constructor (protected ctx: MainContext, protected locals: Locals, params: {}) {
    this.client = new VaultClient(CLOUD_URL)
    this.failed = false
    this.bindClientEvents()
    this.bindRuntimeEvents()
  }

  protected bindRuntimeEvents (): void {
    const { authManager, runtimeManager, dialog, storeManager } = this.locals
    let justRegistered = false
    runtimeManager.on('before-auth', async (task) => {
      justRegistered = !authManager.registered
    })

    runtimeManager.on('after-private-settings', async (task) => {
      if (justRegistered) {
        const confirm = await dialog.confirmation({
          message: 'If you already have a cloud vault account, you can start the wallet using your cloud data. \nDo you want to login into the cloud vault?',
          title: 'Authentication'
        })
        if (confirm === true) {
          await this.loginTask(task)
        }
      } else {
        const privateSettings = storeManager.getStore('private-settings')
        const cloud = await privateSettings.get('cloud')
        if (cloud) {
          const asyncLogin = this.loginTask(task, cloud)
          handlePromise(this.locals, asyncLogin)
        }
      }
    })
  }

  protected bindClientEvents (): void {
    const { sharedMemoryManager: shm } = this.locals

    this.client.on('connected', (t) => {
      this.locals.toast.show({
        message: 'Cloud Vault connected',
        details: 'Your cloud vault has been sucessfully connected!',
        type: 'success'
      })

      shm.update(mem => ({
        ...mem,
        cloudVaultData: {
          state: 'connected'
        }
      }))
    })

    this.client.on('disconnected', () => {
      this.locals.toast.show({
        message: 'Cloud Vault disconnected',
        details: 'Your cloud vault has been disconnected!',
        type: 'error'
      })

      shm.update(mem => ({
        ...mem,
        cloudVaultData: {
          state: 'disconnected'
        }
      }))
    })
  }

  async clientInitialized (errorMessage: string): Promise<void> {
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
  }

  get isConnected(): boolean {
    return this.locals.sharedMemoryManager.memory.cloudVaultData.state === 'connected'
  }

  async getLoginData (errorMessage: string): Promise<CloudVaultSettings> {
    const { dialog } = this.locals
    const loginData = await dialog.form<CloudVaultSettings>({
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

  async registerTask (task: LabeledTaskHandler, cloud?: CloudVaultSettings): Promise<void> {
    const errorMessage = 'Vault user registration error'

    await this.clientInitialized(errorMessage)

    if (cloud === undefined) {
      cloud = await this.getLoginData(errorMessage)
    }
    const vc = await this.getRegistrationCredential(errorMessage)
    const publicJwk = await this.client.getServerPublicKey()

    const data = await jweEncrypt(
      Buffer.from(JSON.stringify({
        did: vc.identity,
        username: cloud.username,
        authkey: await VaultClient.computeAuthKey(CLOUD_URL, cloud.username, cloud.password)
      })),
      publicJwk as JWK,
      'A256GCM'
    )

    const res = `${CLOUD_URL}${this.client.wellKnownCvsConfiguration?.registration_configuration.registration_endpoint.replace('{data}', data) ?? ''}`
    await shell.openExternal(res)
  }

  async loginTask (task: LabeledTaskHandler, cloud?: CloudVaultSettings): Promise<void> {
    const { sharedMemoryManager: shm } = this.locals
    const errorMessage = 'Vault login error'

    await this.clientInitialized(errorMessage)

    let fixedCloud: CloudVaultSettings
    if (cloud === undefined) {
      fixedCloud = await this.getLoginData(errorMessage)
    } else {
      fixedCloud = cloud
    }

    try {
      await this.client.login(fixedCloud.username, fixedCloud.password)
      shm.update(mem => ({
        ...mem,
        cloudVaultData: {
          state: 'connected'
        },
        settings: {
          ...mem.settings,
          cloud: {
            ...fixedCloud,
            token: this.client.token as string
          }
        }
      }))
    } catch (err) {
      if (err instanceof VaultError) {
        if (checkErrorType(err, 'invalid-credentials')) {
          throw new WalletDesktopError('Invalid credentials', {
            severity: 'error',
            message: errorMessage,
            details: 'Invalid credentials.'
          })
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

  async startVaultSyncTask (task: LabeledTaskHandler): Promise<void> {
    const { dialog } = this.locals
    const errorMessage = 'Vault synchronization error'

    const login: DialogOption = { id: 0, text: 'Yes, start login', context: 'success' }
    const register: DialogOption = { id: 1, text: 'No, register a new account', context: 'success' }
    const cancel: DialogOption = { id: 2, text: 'Cancel', context: 'danger' }

    const loginOrRegister = await dialog.select({
      title: 'Cloud Vault',
      message: 'To start the cloud vault synchronization you need a valid cloud vault account. ',
      values: [login, register, cancel],
      allowCancel: true,
      getText: (v) => v.text,
      getContext: (v) => v.context
    })

    let cloud: CloudVaultSettings
    switch (loginOrRegister?.id) {
      case login.id:
        cloud = await this.getLoginData(errorMessage)
        await this.loginTask(task, cloud)
        break

      case register.id:
        cloud = await this.getLoginData(errorMessage)
        await this.registerTask(task, cloud)
        break
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
      message: 'Do you want to remove all the data of your vault?',
      acceptMsg: 'Yes',
      rejectMsg: 'No'
    })
    if (confirm !== true) {
      return
    }

    await this.client.deleteStorage().catch(...handleErrorCatch(this.locals))
    await this.logout()
  }

  async register (): Promise<void> {
    const { taskManager } = this.locals
    const taskInfo: TaskDescription = { title: 'Register Cloud User' }
    await taskManager.createTask('labeled', taskInfo, async (task) => {
      return await this.registerTask(task)
    })
  }

  async logout (): Promise<void> {
    this.client.logout()
    await this.locals.storeManager.onStopCloudService()
  }

  async login (): Promise<void> {
    const { taskManager } = this.locals
    const taskInfo: TaskDescription = { title: 'Login Cloud User' }
    await taskManager.createTask('labeled', taskInfo, async (task) => {
      return await this.loginTask(task)
    })
  }

  async updateStorage (storage: Buffer, timestamp?: number): Promise<number> {
    return await this.client.updateStorage({
      storage: storage,
      timestamp
    })
  }
}
