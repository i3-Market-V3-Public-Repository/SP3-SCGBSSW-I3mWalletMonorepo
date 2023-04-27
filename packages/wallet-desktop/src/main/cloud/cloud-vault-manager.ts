import { CbOnEventFn as ClientCallback, VaultClient, VaultStorage, VAULT_STATE } from '@i3m/cloud-vault-client'
import { jweEncrypt, JWK } from '@i3m/non-repudiation-library'

import { CloudVaultPrivateSettings, CloudVaultPublicSettings, Credentials, TaskDescription } from '@wallet/lib'
import { getVersionDate, handleError, handleErrorCatch, handlePromise, LabeledTaskHandler, Locals, logger, MainContext, SyncTimestamps, WalletDesktopError } from '@wallet/main/internal'
import { StoresBundle } from '../store/store-bundle'
import { CloudVaultFlows } from './cloud-vault-flows'

interface Params {
  privateCloud?: CloudVaultPrivateSettings
  publicCloud?: CloudVaultPublicSettings
}

interface VaultClientBinding {
  client: VaultClient
  closeCurrentClient: () => void
}

export class CloudVaultManager {
  protected failed: boolean
  protected flows: CloudVaultFlows
  protected pendingSyncs: number[]
  protected clientBinding?: VaultClientBinding

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

  constructor (protected ctx: MainContext, protected locals: Locals, params: Params) {
    this.flows = new CloudVaultFlows(locals)
    this.failed = false
    this.pendingSyncs = []
    this.bindRuntimeEvents()
    this.bindSyncEvents()
    // this.bindClientEvents()
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

  protected bindSyncEvents (): void {
    const { syncManager } = this.locals

    // FIXME: incomplete...
    syncManager.on('conflict', async (ev) => {
      const direction = await this.flows.askConflictResolution(ev.localTimestamp, ev.remoteTimestamp)
      await ev.resolve(direction, true) // After event resolution always force
    })

    syncManager.on('update', async (ev) => {
      switch (ev.direction) {
        case 'pull':
          await this.restoreVault()
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

  protected async createClientBinding (): Promise<VaultClient> {
    if (this.clientBinding !== undefined) {
      return this.clientBinding.client
    }

    const { sharedMemoryManager: shm, syncManager } = this.locals

    const url = await this.flows.askCloudVaultUrl()
    const client = new VaultClient(url, {
      // TO-DO: add retry options to params
      defaultRetryOptions: {
        retries: 1 * 60 / 5, // one retry every 5 seconds for 5 minutes hours
        retryDelay: 5000
      }
    })

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
      const promise = syncManager.sync({ remoteTimestamp })
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

    client.on('state-changed', onStateChange)
    client.on('storage-updated', onStorageUpdated)
    client.on('empty-storage', onEmptyStorage)
    client.on('sync-start', onSyncStart)
    client.on('sync-stop', onSyncStop)

    this.clientBinding = {
      client,
      closeCurrentClient: () => {
        delete this.clientBinding

        client.off('state-changed', onStateChange)
        client.off('storage-updated', onStorageUpdated)
        client.off('sync-start', onSyncStart)
        client.off('sync-stop', onSyncStop)

        client.close()
      }
    }

    return client
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
      remote: this.clientBinding?.client.timestamp,
      local: shm.memory.settings.public.cloud?.timestamp
    }
  }

  // *************** Task Methods *************** //
  // FIXME: pending update
  protected async registerTask (task: LabeledTaskHandler, cloud?: CloudVaultPrivateSettings): Promise<Credentials> {
    const errorMessage = 'Vault user registration error'
    const { sharedMemoryManager } = this.locals

    const client = this.createClientBinding()

    let credentials = cloud?.credentials
    if (credentials === undefined) {
      credentials = await this.flows.askCredentials(errorMessage)
    }
    await this.flows.askPasswordConfirmation(credentials)

    const vc = await this.flows.askRegistrationCredential(errorMessage)
    const publicJwk = await client.getServerPublicKey()

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

  protected async loginTask (task: LabeledTaskHandler, cloud?: CloudVaultPrivateSettings): Promise<void> {
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
      const client = await this.createClientBinding()
      // await this.client.initialized

      let credentials = cloud?.credentials
      if (credentials === undefined) {
        credentials = await this.flows.askCredentials(errorMessage)
      }

      await client.login(credentials.username, credentials.password, publicCloudSettings?.timestamp)
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

  // *************** Client Methods *************** //
  async delete (): Promise<void> {
    if (this.clientBinding === undefined) {
      throw new WalletDesktopError('delete vault error', {
        message: 'Delete Vault',
        severity: 'error',
        details: 'You cannot delete a vault if the vault client is not created. Are you already logged in?'
      })
    }

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
    await this.clientBinding.client.deleteStorage().catch(...handleErrorCatch(this.locals))
    await this.logout()
  }

  async stop (): Promise<void> {
    if (this.clientBinding === undefined) {
      throw new WalletDesktopError('stop vault error', {
        message: 'Stop Vault Client',
        severity: 'error',
        details: 'You cannot stop the vault client if it is not created yet. Are you already logged in?'
      })
    }

    // We modify the state before the logout to remove the disconnected toast!
    await this.locals.storeManager.onStopCloudService()
    this.clientBinding.closeCurrentClient()
  }

  async logout (): Promise<void> {
    if (this.clientBinding === undefined) {
      throw new WalletDesktopError('stop vault error', {
        message: 'Stop Vault Client',
        severity: 'error',
        details: 'You cannot log out if you are not logged in.'
      })
    }

    // We modify the state before the logout to remove the disconnected toast!
    await this.locals.storeManager.onStopCloudService()
    this.clientBinding.client.logout()
  }

  async register (): Promise<void> {
    const { taskManager } = this.locals
    const taskInfo: TaskDescription = { title: 'Register Cloud User' }
    await taskManager.createTask('labeled', taskInfo, async (task) => {
      return await this.registerTask(task)
    })
  }

  async login (cloud?: CloudVaultPrivateSettings): Promise<void> {
    const { taskManager } = this.locals
    const taskInfo: TaskDescription = { title: 'Login Cloud User' }
    await taskManager.createTask('labeled', taskInfo, async (task) => {
      return await this.loginTask(task, cloud)
    })
  }

  // *************** Sync *************** //
  async storeVault (force = false): Promise<void> {
    if (this.isDisconnected || this.clientBinding === undefined) {
      return
    }

    const { sharedMemoryManager: sh, storeManager } = this.locals

    const client = this.clientBinding.client
    const cloud = sh.memory.settings.public.cloud
    const bundle = await storeManager.bundleStores()
    const bundleJSON = JSON.stringify(bundle)
    const storage = Buffer.from(bundleJSON)
    const vault: VaultStorage = {
      storage, timestamp: cloud?.timestamp
    }

    const versionDate = getVersionDate(vault.timestamp)
    logger.debug(`Uploading to cloud vault (${client.serverUrl}) the version (${versionDate})`)
    const newTimestamp = await client.updateStorage(vault, force)

    await storeManager.onCloudSynced(newTimestamp)
  }

  async restoreVault (vault?: VaultStorage): Promise<void> {
    if (this.isDisconnected || this.clientBinding === undefined) {
      return
    }

    const { storeManager } = this.locals
    
    if (vault === undefined) {
      const client = this.clientBinding.client
      vault = await client.getStorage()
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
