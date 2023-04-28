import { CbOnEventFn as ClientCallback, VaultClient, VaultStorage, VAULT_STATE } from '@i3m/cloud-vault-client'

import { CloudVaultPrivateSettings, CloudVaultPublicSettings, Credentials, TaskDescription } from '@wallet/lib'
import { getVersionDate, handleError, handleErrorCatch, handlePromise, LabeledTaskHandler, Locals, logger, MainContext, SyncTimestamps, WalletDesktopError } from '@wallet/main/internal'
import { StoresBundle } from '../store/store-bundle'
import { CloudVaultFlows } from './cloud-vault-flows'

interface Params {
  privateCloud?: CloudVaultPrivateSettings
  publicCloud?: CloudVaultPublicSettings
}

export class CloudVaultManager {
  protected failed: boolean
  protected flows: CloudVaultFlows
  protected pendingSyncs: number[]
  protected client: VaultClient

  // Static initialization
  static async initialize (ctx: MainContext, locals: Locals): Promise<CloudVaultManager> {
    const { sharedMemoryManager: shm } = locals

    const privateCloud = shm.memory.settings.private.cloud
    const publicCloud = shm.memory.settings.public.cloud

    return new CloudVaultManager(ctx, locals, {
      privateCloud,
      publicCloud
    })
  }

  constructor (protected ctx: MainContext, protected locals: Locals, params: Params) {
    this.flows = new CloudVaultFlows(locals)
    this.failed = false
    this.pendingSyncs = []
    this.client = new VaultClient({
      // TO-DO: add retry options to params
      defaultRetryOptions: {
        retries: 1 * 60 / 5, // one retry every 5 seconds for 5 minutes hours
        retryDelay: 5000
      }
    })
    this.bindRuntimeEvents()
    this.bindSyncEvents()
    this.bindClientEvents()
  }

  protected bindRuntimeEvents (): void {
    const { authManager, runtimeManager, sharedMemoryManager: shm } = this.locals

    // Cloud vault workflow
    runtimeManager.on('cloud-auth', async (task) => {
      if (authManager.justRegistered) {
        await this.firstTimeSync(task)
      } else {
        const cloud = shm.memory.settings.private.cloud
        if (cloud?.credentials !== undefined) {
          const asyncLogin = this.login(cloud.credentials)
          handlePromise(this.locals, asyncLogin)
        }
      }
    })
  }

  protected bindSyncEvents (): void {
    const { syncManager } = this.locals

    syncManager.on('conflict', async (ev) => {
      const direction = await this.flows.askConflictResolution(this.timestamps.local, this.timestamps.remote)
      await ev.resolve(direction, true) // After event resolution always force
    })

    syncManager.on('update', async (ev) => {
      switch (ev.direction) {
        case 'pull':
          await this.restoreVault(ev.vault)
          break

        case 'push':
          await this.storeVault(ev.force)
          break

        case 'none':
          logger.info('No synchronization required')
          break
      }
    })
  }

  protected bindClientEvents (): void {
    const { sharedMemoryManager: shm, syncManager } = this.locals

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
      const promise = syncManager.sync({ timestamps: this.timestamps })
      handlePromise(this.locals, promise)
    }

    const onEmptyStorage: ClientCallback<'empty-storage'> = () => {
      const promise = syncManager.sync({ direction: 'push' })
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
  }

  protected async firstTimeSync (task: LabeledTaskHandler): Promise<void> {
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
    }

    if (sync) {
      await this.locals.syncManager.sync({
        direction: 'pull',
        timestamps: this.timestamps,
        force: true
      })
    }
  }

  get isConnected (): boolean {
    return this.locals.sharedMemoryManager.memory.cloudVaultData.state >= VAULT_STATE.CONNECTED
  }

  get isDisconnected (): boolean {
    return this.locals.sharedMemoryManager.memory.cloudVaultData.state < VAULT_STATE.CONNECTED
  }

  get timestamps (): SyncTimestamps {
    const { sharedMemoryManager: shm } = this.locals
    return {
      remote: this.client.timestamp,
      local: shm.memory.settings.public.cloud?.timestamp
    }
  }

  // *************** Task Methods *************** //
  protected async registerTask (task: LabeledTaskHandler): Promise<void> {
    const errorMessage = 'Vault user registration error'
    const { sharedMemoryManager: shm } = this.locals

    shm.update(mem => ({
      ...mem,
      cloudVaultData: {
        ...mem.cloudVaultData,
        blocking: true
      }
    }))

    try {
      await this.initializeClientIfNeeded()

      const credentials = await this.flows.askCredentials(errorMessage)
      await this.flows.askPasswordConfirmation(credentials)

      const vc = await this.flows.askRegistrationCredential(errorMessage)
      if (vc.identity === undefined) {
        throw new WalletDesktopError('Invalid identity', {
          message: 'Invalid verifiable credential',
          details: `The verifiable credential '${vc.id}' has no associated identity`
        })
      }

      const username = credentials.username
      const url = await this.client.getRegistrationUrl(credentials.username, credentials.password, vc.identity)
      shm.update((mem) => ({
        ...mem,
        cloudVaultData: {
          ...mem.cloudVaultData,
          registration: { url, username }
        }
      }))
    } finally {
      shm.update(mem => ({
        ...mem,
        cloudVaultData: {
          ...mem.cloudVaultData,
          blocking: false
        }
      }))
    }
  }

  protected async loginTask (task: LabeledTaskHandler, optCredentails?: Credentials): Promise<void> {
    const { sharedMemoryManager: shm } = this.locals
    const errorMessage = 'Vault login error'

    const publicCloudSettings = shm.memory.settings.public.cloud
    shm.update(mem => ({
      ...mem,
      cloudVaultData: {
        ...mem.cloudVaultData,
        blocking: true
      }
    }))

    try {
      await this.initializeClientIfNeeded()
      const credentials = await this.flows.askCredentials(errorMessage, { credentials: optCredentails, store: true })
      await this.client.login(credentials.username, credentials.password, publicCloudSettings?.timestamp)
      shm.update(mem => ({
        ...mem,
        cloudVaultData: {
          ...mem.cloudVaultData,
          registration: undefined
        }
      }))
    } finally {
      shm.update(mem => ({
        ...mem,
        cloudVaultData: {
          ...mem.cloudVaultData,
          blocking: false
        }
      }))
    }
  }

  // *************** Client Methods *************** //
  async initializeClientIfNeeded (): Promise<void> {
    // If the url is different from the current one close the vault.
    const url = await this.flows.askCloudVaultUrl()
    if (this.client.serverUrl !== url) {
      await this.client.close()
    }

    // If the vault is not initialized, initialize it.
    const state = await this.client.state
    if (state === VAULT_STATE.NOT_INITIALIZED) {
      await this.client.init(url)
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
    // We modify the state before the logout to remove the disconnected toast!
    await this.locals.storeManager.onStopCloudService()
    await this.client.close()
  }

  async logout (): Promise<void> {
    // We modify the state before the logout to remove the disconnected toast!
    await this.locals.storeManager.onStopCloudService()

    const { sharedMemoryManager: shm } = this.locals
    if (shm.memory.cloudVaultData.registration !== undefined) {
      shm.update(mem => ({
        ...mem,
        cloudVaultData: {
          ...mem.cloudVaultData,
          registration: undefined
        }
      }))
    }

    if (await this.client.state > VAULT_STATE.LOGGED_IN) {
      await this.client.logout()
    }
  }

  async register (): Promise<void> {
    const { taskManager } = this.locals
    const taskInfo: TaskDescription = { title: 'Register Cloud User' }
    await taskManager.createTask('labeled', taskInfo, async (task) => {
      return await this.registerTask(task)
    })
  }

  async login (credentials?: Credentials): Promise<void> {
    const { taskManager } = this.locals
    const taskInfo: TaskDescription = { title: 'Login Cloud User' }
    await taskManager.createTask('labeled', taskInfo, async (task) => {
      return await this.loginTask(task, credentials)
    })
  }

  // *************** Sync *************** //
  async storeVault (force = false): Promise<void> {
    if (this.isDisconnected) {
      return
    }

    const { sharedMemoryManager: sh, storeManager } = this.locals

    const cloud = sh.memory.settings.public.cloud
    const bundle = await storeManager.bundleStores()
    const bundleJSON = JSON.stringify(bundle)
    const storage = Buffer.from(bundleJSON)
    const vault: VaultStorage = {
      storage, timestamp: cloud?.timestamp
    }

    const versionDate = getVersionDate(vault.timestamp)
    logger.debug(`Uploading to cloud vault (${this.client.serverUrl ?? 'without url!'}) the version (${versionDate})`)
    const newTimestamp = await this.client.updateStorage(vault, force)

    await storeManager.onCloudSynced(newTimestamp)
  }

  async restoreVault (vault?: VaultStorage): Promise<void> {
    if (this.isDisconnected) {
      return
    }

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
}
