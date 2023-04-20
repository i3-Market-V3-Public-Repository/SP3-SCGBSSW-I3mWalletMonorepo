import { CbOnEventFn as ClientCallback, checkErrorType, VaultClient, VaultError, VaultStorage, VAULT_STATE } from '@i3m/cloud-vault-client'
import { jweEncrypt, JWK } from '@i3m/non-repudiation-library'

import { CloudVaultPrivateSettings, CloudVaultPublicSettings, Credentials, DEFAULT_CLOUD_URL, TaskDescription } from '@wallet/lib'
import { filledString, getVersionDate, handleError, handleErrorCatch, handlePromise, LabeledTaskHandler, Locals, logger, MainContext, WalletDesktopError } from '@wallet/main/internal'
import { StoresBundle } from '../store/store-bundle'
import { CloudVaultFlows } from './cloud-vault-flows'

interface SynchronizeContext {
  remoteTimestamp?: number
  publicCloud?: CloudVaultPublicSettings
  direction?: 'pull' | 'push' | 'conflict' | 'none'
  force?: boolean
}

interface Params {
  privateCloud?: CloudVaultPrivateSettings
  publicCloud?: CloudVaultPublicSettings
}

export class CloudVaultManager extends CloudVaultFlows {
  protected client: VaultClient
  protected failed: boolean
  protected pendingSyncs: number[]
  protected unbindClientEvents: (() => void) | undefined

  // Static initialization
  static async initialize (ctx: MainContext, locals: Locals): Promise<CloudVaultManager> {
    const { storeManager } = locals
    const privSettings = storeManager.getStore('private-settings')
    const privateCloud = await privSettings.get('cloud')

    const pubSettings = storeManager.getStore('public-settings')
    const publicCloud = await pubSettings.get('cloud')

    return new CloudVaultManager(ctx, locals, {
      privateCloud,
      publicCloud
    })
  }

  static buildCloudUrl (url?: string): string {
    return filledString(url, DEFAULT_CLOUD_URL)
  }

  constructor (protected ctx: MainContext, protected locals: Locals, params: Params) {
    super(locals)

    const url = CloudVaultManager.buildCloudUrl(params.publicCloud?.url)
    this.client = this.buildClient(url)
    this.failed = false
    this.pendingSyncs = []
    this.bindRuntimeEvents()
    this.bindClientEvents()
  }

  protected bindRuntimeEvents (): void {
    const { authManager, runtimeManager, storeManager } = this.locals

    // Cloud vault workflow
    runtimeManager.on('cloud-auth', async (task) => {
      if (authManager.justRegistered) {
        await this.firstTimeSync(task)
      } else {
        const privateSettings = storeManager.getStore('private-settings')
        const cloud = await privateSettings.get('cloud')
        if (cloud?.credentials !== undefined) {
          const asyncLogin = this.login(cloud)
          handlePromise(this.locals, asyncLogin)
        }
      }
    })
  }

  protected resetClient (url: string, force = false): void {
    const newUrl = CloudVaultManager.buildCloudUrl(url)
    if (this.client.serverUrl !== newUrl || force) {
      const client = this.buildClient(newUrl)

      if (this.client !== undefined) {
        this.client.close()
      }
      this.client = client
      this.bindClientEvents()
    }
  }

  public restartClient (): void {
    this.resetClient(this.client.serverUrl, true)
  }

  protected buildClient (url: string): VaultClient {
    if (this.unbindClientEvents !== undefined) this.unbindClientEvents()

    const client = new VaultClient(url, {
      // TO-DO: add retry options to params
      defaultRetryOptions: {
        retries: 1 * 60 / 5, // one retry every 5 seconds for 5 minutes hours
        retryDelay: 5000
      }
    })

    return client
  }

  protected bindClientEvents (): void {
    const { sharedMemoryManager: shm } = this.locals
    const onStateChange: ClientCallback<'state-changed'> = (state) => {
      const prevState = shm.memory.cloudVaultData.state

      shm.update(mem => ({
        ...mem,
        cloudVaultData: {
          ...mem.cloudVaultData,
          state
        }
      }))

      if (prevState < VAULT_STATE.CONNECTED && state === VAULT_STATE.CONNECTED) {
        this.locals.toast.show({
          message: 'Cloud Vault connected',
          type: 'success'
        })
      } else if (prevState === VAULT_STATE.CONNECTED && state < VAULT_STATE.CONNECTED) {
        this.locals.toast.show({
          message: 'Cloud Vault disconnected',
          details: 'Check your internet connection please',
          type: 'error'
        })
      }
    }

    const onStorageUpdated: ClientCallback<'storage-updated'> = (remoteTimestamp) => {
      const versionDate = getVersionDate(remoteTimestamp)
      logger.debug(`Getting a new cloud vault version (${versionDate})`)
      const promise = this.synchronize({ remoteTimestamp })
      handlePromise(this.locals, promise)
    }

    const onEmptyStorage: ClientCallback<'empty-storage'> = () => {
      const promise = this.synchronize({ direction: 'push' })
      handlePromise(this.locals, promise)
    }

    const onSyncStart: ClientCallback<'sync-start'> = (startTs) => {
      const pairing = shm.memory.cloudVaultData.syncing
      if (!pairing) {
        shm.update(mem => ({
          ...mem,
          cloudVaultData: {
            ...mem.cloudVaultData,
            syncing: true
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
            ...mem.cloudVaultData,
            syncing: false
          }
        }))
      }
    }

    this.client.on('state-changed', onStateChange)
    this.client.on('storage-updated', onStorageUpdated)
    this.client.on('empty-storage', onEmptyStorage)
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

    const loginBuilder = dialog.useOptionsBuilder()
    loginBuilder.add('No', 'danger')
    const login = loginBuilder.add('Yes')

    let sync = false
    while (!sync) {
      const option = await dialog.select({
        title: 'Secure Cloud Vault',
        message: 'If you already have a backup in a cloud vault server, do you want to load it?',
        ...loginBuilder
      })

      if (loginBuilder.compare(option, login)) {
        try {
          await this.loginTask(task)
          sync = true
          continue
        } catch (err: unknown) {
          await handleError(this.locals, err)
        }
      } else {
        break
      }
      // else if (loginBuilder.compare(option, register)) {
      //   while (true) {
      //     const credentials = await this.registerTask(task)
      //     const loginBackBuilder = dialog.useOptionsBuilder()
      //     const relogin = loginBuilder.add('Login with same credentials')
      //     loginBuilder.add('Go back')
      //     const option = await dialog.select({
      //       title: 'Cloud Vault Registration',
      //       message: 'Bla bla',
      //       ...loginBuilder
      //     })

      //     if (loginBackBuilder.compare(relogin, option)) {
      //       try {
      //         await this.loginTask(task, { credentials })
      //         sync = true
      //       } catch (err: unknown) {
      //         await handleError(this.locals, err)
      //       }
      //     } else {
      //       break
      //     }
      //   }
      // } else {
      //   break
      // }
    }

    if (sync) {
      await this.synchronize({
        direction: 'pull',
        force: true
      })
    }
  }

  get isConnected (): boolean {
    return this.locals.sharedMemoryManager.memory.cloudVaultData.state === VAULT_STATE.CONNECTED
  }

  get isDisconnected (): boolean {
    return this.locals.sharedMemoryManager.memory.cloudVaultData.state < VAULT_STATE.CONNECTED
  }

  async registerTask (task: LabeledTaskHandler, cloud?: CloudVaultPrivateSettings): Promise<Credentials> {
    const errorMessage = 'Vault user registration error'
    const { sharedMemoryManager } = this.locals

    const url = await this.getCloudVaultUrl()
    this.resetClient(url)
    await this.client.initialized

    let credentials = cloud?.credentials
    if (credentials === undefined) {
      credentials = await this.getCredentials(errorMessage)
    }
    await this.confirmPassword(credentials)

    const vc = await this.getRegistrationCredential(errorMessage)
    const publicJwk = await this.client.getServerPublicKey()

    const data = await jweEncrypt(
      Buffer.from(JSON.stringify({
        did: vc.identity,
        username: credentials.username,
        authkey: await VaultClient.computeAuthKey(this.client.serverUrl, credentials.username, credentials.password)
      })),
      publicJwk as JWK,
      'A256GCM'
    )

    const username = credentials.username
    const registrationUrl = `${this.client.wellKnownCvsConfiguration?.registration_configuration.registration_endpoint.replace('{data}', data) ?? ''}`
    sharedMemoryManager.update((mem) => ({
      ...mem,
      cloudVaultData: {
        ...mem.cloudVaultData,
        registration: {
          url: registrationUrl,
          username
        }
      }
    }))

    return credentials
  }

  async loginTask (task: LabeledTaskHandler, cloud?: CloudVaultPrivateSettings): Promise<void> {
    const { sharedMemoryManager: shm, storeManager } = this.locals
    const errorMessage = 'Vault login error'

    const publicSettings = storeManager.getStore('public-settings')
    const publicCloudSettings = await publicSettings.get('cloud')
    shm.update(mem => ({
      ...mem,
      cloudVaultData: {
        ...mem.cloudVaultData,
        loggingIn: true
      }
    }))

    try {
      const url = await this.getCloudVaultUrl()
      this.resetClient(url)
      await this.client.initialized

      let credentials = cloud?.credentials
      if (credentials === undefined) {
        credentials = await this.getCredentials(errorMessage)
      }

      await this.client.login(credentials.username, credentials.password, publicCloudSettings?.timestamp)
      await storeManager.onCloudLogin(credentials)
    } finally {
      shm.update(mem => ({
        ...mem,
        cloudVaultData: {
          ...mem.cloudVaultData,
          unsyncedChanges: publicCloudSettings?.unsyncedChanges ?? false,
          loggingIn: false
        }
      }))
    }
  }

  async delete (): Promise<void> {
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

    // We modify the state before the logout to remove the disconnected toast!
    await this.locals.storeManager.onStopCloudService()
    await this.client.deleteStorage().catch(...handleErrorCatch(this.locals))
    await this.logout()
  }

  async stop (): Promise<void> {
    await this.logout()
    this.client.close()
  }

  async register (): Promise<void> {
    const { taskManager } = this.locals
    const taskInfo: TaskDescription = { title: 'Register Cloud User' }
    await taskManager.createTask('labeled', taskInfo, async (task) => {
      return await this.registerTask(task)
    })
  }

  async logout (): Promise<void> {
    // We modify the state before the logout to remove the disconnected toast!
    await this.locals.storeManager.onStopCloudService()
    this.client.logout()
  }

  async login (cloud?: CloudVaultPrivateSettings): Promise<void> {
    const { taskManager } = this.locals
    const taskInfo: TaskDescription = { title: 'Login Cloud User' }
    await taskManager.createTask('labeled', taskInfo, async (task) => {
      return await this.loginTask(task, cloud)
    })
  }

  async updateStorage (vault: VaultStorage, force?: boolean): Promise<number> {
    try {
      const versionDate = getVersionDate(vault.timestamp)
      logger.debug(`Uploading to cloud vault (${this.client.serverUrl}) the version (${versionDate})`)
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

  // Syncronization methods
  async uploadVault (force = false): Promise<void> {
    if (this.isDisconnected) {
      return
    }

    const { sharedMemoryManager: sh, storeManager } = this.locals
    if (sh.memory.settings.private.cloud === undefined) {
      return
    }

    const publicSettings = storeManager.getStore('public-settings')
    const cloud = await publicSettings.get('cloud')

    const bundle = await storeManager.bundleStores()
    const bundleJSON = JSON.stringify(bundle)
    const storage = Buffer.from(bundleJSON)

    const newTimestamp = await this.updateStorage({
      storage, timestamp: cloud?.timestamp
    }, force)

    storeManager.onCloudSynced(newTimestamp).catch((err) => { throw err })
  }

  async restoreVault (vault?: VaultStorage): Promise<void> {
    const { storeManager } = this.locals
    if (vault === undefined) {
      vault = await this.client.getStorage()
    }
    if (vault.timestamp === undefined) {
      throw new WalletDesktopError('Invalid vault timestamp!')
    }

    const versionDate = getVersionDate(vault.timestamp)
    logger.debug(`Restoring from cloud vault version: ${versionDate}`)

    // Parse bundle
    const { storage } = vault
    const bundleJSON = storage.toString()
    const bundle = JSON.parse(bundleJSON) as StoresBundle

    await storeManager.restoreStores(bundle)
    await storeManager.onCloudSynced(vault.timestamp)
  }

  async conflict (syncCtx: SynchronizeContext): Promise<void> {
    const { dialog } = this.locals

    const optionBuilder = dialog.useOptionsBuilder()
    const remote = optionBuilder.add('Remote version')
    const local = optionBuilder.add('Local version')
    optionBuilder.add('Cancel', 'danger')

    const localVersion = getVersionDate(syncCtx.publicCloud?.timestamp)
    const remoteVersion = getVersionDate(syncCtx.remoteTimestamp)

    const response = await dialog.select({
      title: 'Cloud Vault',
      message: `There has been a conflict between the local version from ${localVersion} and the remote version from ${remoteVersion}.\n\n Which version would you want to use?`,
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
      const fixedRemoteTimestamp = syncCtx.remoteTimestamp ?? this.client.timestamp ?? 0
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
        await this.restoreVault()
        break
      }

      case 'push':
        await this.uploadVault(syncCtx.force)
        break

      case 'conflict':
        await this.conflict(syncCtx)
        break

      default:
        logger.info('Already synchronized')
    }
  }
}
