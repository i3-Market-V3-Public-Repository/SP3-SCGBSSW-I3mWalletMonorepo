import { DialogOptionContext, VerifiableCredentialResource } from '@i3m/base-wallet'
import { checkErrorType, VaultClient, VaultError, VaultStorage, VAULT_STATE, CbOnEventFn as ClientCallback } from '@i3m/cloud-vault-client'
import { jweEncrypt, JWK } from '@i3m/non-repudiation-library'
import { shell } from 'electron'

import { CloudVaultPrivateSettings, CloudVaultPublicSettings, TaskDescription, DEFAULT_CLOUD_URL, Credentials } from '@wallet/lib'
import { filledString, handleError, handleErrorCatch, handlePromise, LabeledTaskHandler, Locals, logger, MainContext, WalletDesktopError } from '@wallet/main/internal'

interface DialogOption {
  id: number
  text: string
  context: DialogOptionContext
}

interface SynchronizeContext {
  remoteTimestamp?: number
  publicCloud?: CloudVaultPublicSettings
  direction?: 'pull' | 'push' | 'conflict' | 'none'
  force?: boolean
}

interface Params {
  cloud?: CloudVaultPrivateSettings
}

export class CloudVaultManager {
  protected client: VaultClient
  protected failed: boolean
  protected pendingSyncs: number[]
  protected url: string
  protected unbindClientEvents: (() => void) | undefined

  // Static initialization
  static async initialize (ctx: MainContext, locals: Locals): Promise<CloudVaultManager> {
    const { storeManager } = locals
    const privSettings = storeManager.getStore('private-settings')
    const cloud = await privSettings.get('cloud')

    return new CloudVaultManager(ctx, locals, {
      cloud
    })
  }

  static buildCloudUrl (cloud?: CloudVaultPrivateSettings): string {
    return filledString(cloud?.url, DEFAULT_CLOUD_URL)
  }

  constructor (protected ctx: MainContext, protected locals: Locals, params: Params) {
    this.url = CloudVaultManager.buildCloudUrl(params.cloud)
    this.client = new VaultClient(this.url)
    this.failed = false
    this.pendingSyncs = []
    this.bindClientEvents()
    this.bindRuntimeEvents()
  }

  protected bindRuntimeEvents (): void {
    const { authManager, runtimeManager, storeManager } = this.locals

    runtimeManager.on('cloud-auth', async (task) => {
      if (authManager.justRegistered) {
        await this.firstTimeSync(task)
      } else {
        const privateSettings = storeManager.getStore('private-settings')
        const cloud = await privateSettings.get('cloud')
        if (cloud?.credentials !== undefined) {
          const asyncLogin = this.loginTask(task, cloud.credentials)
          handlePromise(this.locals, asyncLogin)
        }
      }
    })
  }

  protected resetClient (): void {
    const { sharedMemoryManager: shm } = this.locals
    const newUrl = CloudVaultManager.buildCloudUrl(shm.memory.settings.cloud)
    if (this.url !== newUrl) {
      if (this.unbindClientEvents !== undefined) this.unbindClientEvents()
      this.client = new VaultClient(this.url)
      this.bindClientEvents()
      this.url = newUrl
    }
  }

  protected bindClientEvents (): void {
    const { sharedMemoryManager: shm } = this.locals
    const onStateChange: ClientCallback<'state-changed'> = (state) => {
      const prevState = shm.memory.cloudVaultData.state

      if (prevState !== 'connected' && state === VAULT_STATE.CONNECTED) {
        this.locals.toast.show({
          message: 'Cloud Vault connected',
          type: 'success'
        })

        shm.update(mem => ({
          ...mem,
          cloudVaultData: {
            state: 'connected'
          }
        }))
      }

      if (prevState !== 'disconnected' && state === VAULT_STATE.LOGGED_IN) {
        this.locals.toast.show({
          message: 'Cloud Vault disconnected',
          details: 'Check your internet connection please',
          type: 'error'
        })

        shm.update(mem => ({
          ...mem,
          cloudVaultData: {
            state: 'disconnected'
          }
        }))
      }
    }

    const onStorageUpdated: ClientCallback<'storage-updated'> = (remoteTimestamp) => {
      const promise = this.synchronize({ remoteTimestamp })
      handlePromise(this.locals, promise)
    }

    const onSyncStart: ClientCallback<'sync-start'> = (startTs) => {
      const prevState = shm.memory.cloudVaultData.state
      if (prevState !== 'sync') {
        shm.update(mem => ({
          ...mem,
          cloudVaultData: {
            state: 'sync'
          }
        }))
      }
      this.pendingSyncs.push(startTs)
    }

    const onSyncStop: ClientCallback<'sync-stop'> = (startTs) => {
      this.pendingSyncs = this
        .pendingSyncs
        .filter((thisStartTs) => thisStartTs !== startTs)
      if (this.pendingSyncs.length === 0) {
        shm.update(mem => ({
          ...mem,
          cloudVaultData: {
            state: 'connected'
          }
        }))
      }
    }

    this.client.on('state-changed', onStateChange)
    this.client.on('storage-updated', onStorageUpdated)
    this.client.on('sync-start', onSyncStart)
    this.client.on('sync-stop', onSyncStop)

    this.unbindClientEvents = () => {
      this.client.off('state-changed', onStateChange)
      this.client.off('storage-updated', onStorageUpdated)
      this.client.off('sync-start', onSyncStart)
      this.client.off('sync-stop', onSyncStop)
    }
  }

  async firstTimeSync (task: LabeledTaskHandler): Promise<void> {
    const { dialog } = this.locals

    const loginRegisterBuilder = dialog.useOptionsBuilder()
    const login = loginRegisterBuilder.add('Login')
    const register = loginRegisterBuilder.add('Register')
    loginRegisterBuilder.add('Omit', 'danger')

    let sync = false
    while (!sync) {
      const option = await dialog.select({
        title: 'Secure Cloud Vault',
        message: 'Do you want to connect to your secure cloud vault? \nYour cloud vault storage will be restored in this wallet.',
        ...loginRegisterBuilder
      })

      if (loginRegisterBuilder.compare(option, login)) {
        try {
          await this.loginTask(task)
          sync = true
          continue
        } catch (err: unknown) {
          await handleError(this.locals, err)
        }
      } else if (loginRegisterBuilder.compare(option, register)) {
        while (true) {
          const credentials = await this.registerTask(task)
          const loginBackBuilder = dialog.useOptionsBuilder()
          const relogin = loginRegisterBuilder.add('Login with same credentials')
          loginRegisterBuilder.add('Go back')
          const option = await dialog.select({
            title: 'Cloud Vault Registration',
            message: 'Bla bla',
            ...loginRegisterBuilder
          })

          if (loginBackBuilder.compare(relogin, option)) {
            try {
              await this.loginTask(task, credentials)
              sync = true
            } catch (err: unknown) {
              await handleError(this.locals, err)
            }
          } else {
            break
          }
        }
      } else {
        break
      }
    }

    if (sync) {
      await this.synchronize({
        direction: 'pull',
        force: true
      })
    }
  }

  async conflict (syncCtx: SynchronizeContext): Promise<void> {
    const { dialog } = this.locals

    const optionBuilder = dialog.useOptionsBuilder()
    const remote = optionBuilder.add('Remote version')
    const local = optionBuilder.add('Local version')
    optionBuilder.add('Cancel', 'danger')

    const response = await dialog.select({
      title: 'Cloud Vault',
      message: '',
      allowCancel: true,
      ...optionBuilder
    })

    if (optionBuilder.compare(remote, response)) {
      await this.synchronize({ ...syncCtx, direction: 'pull', force: true })
    } else if (optionBuilder.compare(local, response)) {
      await this.synchronize({ ...syncCtx, direction: 'push', force: true })
    }
  }

  async synchronize (syncCtx: SynchronizeContext): Promise<void> {
    const { storeManager } = this.locals
    if (syncCtx.publicCloud === undefined) {
      const publicSettings = storeManager.getStore('public-settings')
      syncCtx.publicCloud = await publicSettings.get('cloud')
    }

    if (syncCtx.direction === undefined) {
      const fixedRemoteTimestamp = syncCtx.remoteTimestamp ?? 0
      const fixedLocalTimestamp = syncCtx.publicCloud?.timestamp ?? 0
      const unsyncedChanges = syncCtx.publicCloud?.unsyncedChanges ?? false

      if (fixedRemoteTimestamp > fixedLocalTimestamp) {
        if (unsyncedChanges && syncCtx.force !== true) {
          syncCtx.direction = 'conflict'
        } else {
          syncCtx.direction = 'pull'
        }
      } else if (unsyncedChanges) {
        syncCtx.direction = 'push'
      } else {
        syncCtx.direction = 'none'
      }
    }

    switch (syncCtx.direction) {
      case 'pull': {
        const vault = await this.client.getStorage()
        await storeManager.restoreStoreBundle(vault)
        break
      }

      case 'push':
        await storeManager.uploadStores(syncCtx.force)
        break

      case 'conflict':
        await this.conflict(syncCtx)
        break

      default:
        logger.info('Already synchronized')
    }
  }

  get isConnected (): boolean {
    return this.locals.sharedMemoryManager.memory.cloudVaultData.state === 'connected'
  }

  get isDisconnected (): boolean {
    return this.locals.sharedMemoryManager.memory.cloudVaultData.state === 'disconnected'
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

  async registerTask (task: LabeledTaskHandler, credentials?: Credentials): Promise<Credentials> {
    const errorMessage = 'Vault user registration error'

    this.resetClient()
    await this.client.initialized

    if (credentials === undefined) {
      credentials = await this.getCredentials(errorMessage)
    }
    const vc = await this.getRegistrationCredential(errorMessage)
    const publicJwk = await this.client.getServerPublicKey()

    const data = await jweEncrypt(
      Buffer.from(JSON.stringify({
        did: vc.identity,
        username: credentials.username,
        authkey: await VaultClient.computeAuthKey(DEFAULT_CLOUD_URL, credentials.username, credentials.password)
      })),
      publicJwk as JWK,
      'A256GCM'
    )

    const res = `${DEFAULT_CLOUD_URL}${this.client.wellKnownCvsConfiguration?.registration_configuration.registration_endpoint.replace('{data}', data) ?? ''}`
    await shell.openExternal(res)

    return credentials
  }

  async loginTask (task: LabeledTaskHandler, credentials?: Credentials): Promise<void> {
    const { sharedMemoryManager: shm, storeManager } = this.locals
    const errorMessage = 'Vault login error'

    this.resetClient()
    await this.client.initialized

    if (credentials === undefined) {
      credentials = await this.getCredentials(errorMessage)
    }

    await this.client.login(credentials.username, credentials.password)
    await storeManager.storeCloudCredentials(credentials)
    shm.update(mem => ({
      ...mem,
      cloudVaultData: {
        state: 'connected'
      }
    }))
  }

  async startVaultSyncTask (task: LabeledTaskHandler): Promise<void> {
    const { dialog } = this.locals
    const errorMessage = 'Vault synchronization error'

    const login: DialogOption = { id: 0, text: 'Yes, start login', context: 'success' }
    const register: DialogOption = { id: 1, text: 'No, register a new account', context: 'success' }
    const cancel: DialogOption = { id: 2, text: 'Cancel', context: 'danger' }

    const loginOrRegister = await dialog.select({
      title: 'Cloud Vault',
      message: 'To start the cloud vault synchronization you need a valid cloud vault account.',
      values: [login, register, cancel],
      allowCancel: true,
      getText: (v) => v.text,
      getContext: (v) => v.context
    })

    let credentials: Credentials
    switch (loginOrRegister?.id) {
      case login.id:
        credentials = await this.getCredentials(errorMessage)
        await this.loginTask(task, credentials)
        break

      case register.id:
        credentials = await this.getCredentials(errorMessage)
        await this.registerTask(task, credentials)
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
    const { sharedMemoryManager: shm } = this.locals
    shm.update(mem => ({
      ...mem,
      cloudVaultData: {
        state: 'disconnected'
      }
    }))
    this.client.logout()
    await this.locals.storeManager.onStopCloudService()
  }

  async login (credentials?: Credentials): Promise<void> {
    const { taskManager } = this.locals
    const taskInfo: TaskDescription = { title: 'Login Cloud User' }
    await taskManager.createTask('labeled', taskInfo, async (task) => {
      return await this.loginTask(task, credentials)
    })
  }

  async updateStorage (vault: VaultStorage, force?: boolean): Promise<number> {
    try {
      return await this.client.updateStorage(vault, force)
    } catch (err: unknown) {
      if (err instanceof VaultError) {
        console.trace(err)
        if (checkErrorType(err, 'conflict')) {
          await this.conflict({
            remoteTimestamp: this.client.timestamp
          })
        }
      }
      throw err
    }
  }
}
