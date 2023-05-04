import { Store } from '@i3m/base-wallet'
import { KeyObject } from 'crypto'
import { existsSync } from 'fs'
import fs from 'fs/promises'

import {
  createDefaultPrivateSettings,
  Credentials, PrivateSettings, PublicSettings, storeChangedAction, StoreClass,
  StoreClasses, StoreModel, StoreModels, StoreSettings, WalletInfo
} from '@wallet/lib'
import {
  fixPrivateSettings,
  fixPublicSettings, handleErrorCatch, isEncryptedStore,
  Locals, logger, MainContext,
  PublicSettingsOptions,
  softwareVersion,
  StoreFeatureOptions
} from '@wallet/main/internal'

import { VAULT_STATE } from '@i3m/cloud-vault-client'
import _ from 'lodash'
import { StoreOptions } from './builders'
import { StoreBag } from './store-bag'
import { StoreBuilder } from './store-builder'
import { StoreBundleData, StoreMetadata, StoresBundle } from './store-bundle'
import { StoreProxyBuilder } from './store-proxy'

const DEFAULT_STORE_SETTINGS: StoreSettings = { type: 'electron-store' }

export class StoreManager extends StoreBag {
  builder: StoreBuilder
  silentBag: StoreBag

  static async initialize (ctx: MainContext, locals: Locals): Promise<StoreManager> {
    return new StoreManager(ctx, locals)
  }

  constructor (protected ctx: MainContext, protected locals: Locals) {
    super()
    this.builder = new StoreBuilder(ctx, locals)
    this.silentBag = new StoreBag()
    this.bindRuntimeEvents()
  }

  protected bindRuntimeEvents (): void {
    const { runtimeManager } = this.locals
    runtimeManager.on('after-launch', async () => {
      await this.loadPublicSettings()
    })

    runtimeManager.on('private-settings', async (task) => {
      // Load encrypted settings
      task.setDetails('Migrating and loading encrypted stores')
      await this.loadPrivateSettings()
    })

    runtimeManager.on('fix-settings', async () => {
      // Fix setting files
      await fixPublicSettings(this.locals)
      await fixPrivateSettings(this.locals)
    })

    runtimeManager.on('wallet-stores', async (task) => {
      // Load encrypted settings
      task.setDetails('Migrating and loading encrypted stores')
      await this.loadWalletStores()
    })
  }

  get defaultStoreSettings (): StoreSettings {
    return this.builder.defaultStoreSettings
  }

  set defaultStoreSettings (value: StoreSettings) {
    this.builder.defaultStoreSettings = value
  }

  protected async handleStoreBackup<T> (storePath: string, options: StoreOptions<T>): Promise<void> {
    const { runtimeManager } = this.locals
    const storeBakPath = `${storePath}.bak`

    if (existsSync(storeBakPath)) {
      // Restore backup if present
      logger.debug(`Restore backup for store: ${storePath}`)
      const storeBakData = await fs.readFile(storeBakPath)
      if (storeBakData.length === 0) {
        if (existsSync(storePath)) {
          await fs.rm(storePath)
        }
      } else {
        await fs.copyFile(storeBakPath, storePath)
      }
    } else if (existsSync(storePath)) {
      // Backup if previous settings
      logger.debug(`Create backup for store: ${storePath}`)
      await fs.copyFile(storePath, storeBakPath)
    } else {
      // Backup if previous settings
      logger.debug(`Create empty backup for store: ${storePath}`)
      await fs.writeFile(storeBakPath, '')
    }

    // Remove backup after migration
    runtimeManager.on('after-migration', async () => {
      logger.debug(`Remove backup for store: ${storePath}`)
      await fs.rm(storeBakPath)
    })
  }

  // Loaders
  public async loadPublicSettings (): Promise<void> {
    const options: PublicSettingsOptions = {
      defaults: {
        version: softwareVersion(this.locals)
      },
      onBeforeBuild: async (storePath, opts) => {
        await this.handleStoreBackup(storePath, opts)
      }
    }

    // NOTE: Public settings must always be not encrypted and using the electorn store.
    // This guarantees compatibilities with future versions!
    const [publicSettings, fixedOptions] = await this.builder.buildStore<PublicSettings>({ ...options, storeType: 'electron-store' })
    const publicMetadata: StoreMetadata<'public-settings'> = {
      type: 'public-settings',
      args: [],
      options: fixedOptions
    }

    // Store on store bag
    this.setStore(publicSettings, publicMetadata, 'public-settings')

    // Backup initial public settings data
    const publicSettingsData = await publicSettings.getStore()
    this.ctx.initialPublicSettings = _.cloneDeep(publicSettingsData)

    // Store settings inside shared memory
    const { sharedMemoryManager: shm } = this.locals
    shm.update((mem) => ({
      ...mem,
      settings: {
        ...mem.settings,
        public: publicSettingsData
      }
    }))

    // Set default StoreBuilder settings
    this.defaultStoreSettings = shm.memory.settings.public.store ?? DEFAULT_STORE_SETTINGS
  }

  public async loadPrivateSettings (): Promise<void> {
    const { keysManager, sharedMemoryManager: shm } = this.locals
    const { version, auth, cloud, store, enc, ...rest } = shm.memory.settings.public
    const options: Partial<StoreOptions<any>> = {
      defaults: Object.assign({}, createDefaultPrivateSettings(), rest),
      fileExtension: 'enc.json',
      encryptionKey: await keysManager.computeSettingsKey(),
      onBeforeBuild: async (storePath, opts) => {
        await this.handleStoreBackup(storePath, opts)
      }
    }

    const [privateSettings, fixedOptions] = await this.builder.buildStore<PrivateSettings>({ ...options })

    // Store on store bag
    this.sendStoreToBag(privateSettings, fixedOptions, 'private-settings')

    // Backup initial public settings data
    const privateSettingsData = await privateSettings.getStore()
    this.ctx.initialPrivateSettings = _.cloneDeep(privateSettingsData)

    // Store settings inside shared memory
    shm.update((mem) => ({
      ...mem,
      settings: {
        ...mem.settings,
        private: privateSettingsData
      }
    }))
  }

  public async loadWalletStores (): Promise<void> {
    const { walletFactory, sharedMemoryManager: shm, toast } = this.locals
    const walletSettings = shm.memory.settings.private.wallet
    const walletOptionsBuilders = Object
      .values(walletSettings.wallets)
      .map((wallet) => {

        let storeFeature
        try {
          storeFeature = walletFactory.getWalletFeatureByType<StoreFeatureOptions>(wallet.package, 'store')
        } catch (err) {
          toast.show({
            message: 'Wallet Stores',
            details: `Could not load store for wallet ${wallet.name}`,
            type: 'warning'
          })
        }

        return { wallet, storeFeature }
      })
      .filter(({ storeFeature }) => storeFeature !== undefined)
      .map(({ wallet, storeFeature }) => {
        return {
          walletName: wallet.name,
          wallet,
          storeFeature
        }
      })

    for (const { walletName, wallet, storeFeature } of walletOptionsBuilders) {
      const options = await this.builder.buildWalletStoreOptions(wallet, storeFeature?.opts)
      const [walletStore, fixedOptions] = await this.builder.buildStore({ ...options })
      this.sendStoreToBag(walletStore, fixedOptions, 'wallet', walletName)
    }
  }

  // Store Bag methods
  public async buildWalletStore (walletInfo: WalletInfo): Promise<void> {
    const { walletFactory } = this.locals
    const storeFeature = walletFactory.getWalletFeatureByType<StoreFeatureOptions>(walletInfo.package, 'store')
    const options = await this.builder.buildWalletStoreOptions(walletInfo, storeFeature?.opts)
    const [walletStore, fixedOptions] = await this.builder.buildStore({ ...options })
    this.sendStoreToBag(walletStore, fixedOptions, 'wallet', walletInfo.name)
  }

  public deleteStoreById (storeId: string): void {
    super.deleteStoreById(storeId)
    this.silentBag.deleteStoreById(storeId)
  }

  protected sendStoreToBag <T extends StoreClass> (
    store: Store<StoreModels[T]>,
    options: StoreOptions<StoreModels[T]>,
    type: T,
    ...args: StoreClasses[T]
  ): void {
    const { actionReducer } = this.locals
    const metadata: StoreMetadata<T> = { type, args, options }

    const storeProxy = new StoreProxyBuilder(store)
    const beforeChange = async (): Promise<void> => {
      await this.onBeforeChange(type, store)
    }
    const afterChange = async (): Promise<void> => {
      actionReducer
        .reduce(storeChangedAction.create([type, store]))
        .catch(...handleErrorCatch(this.locals))
    }
    // TODO: Unbind events on delete store, for instance, when syncing a different store set
    // const afterDelete = async (): Promise<void> => {
    //   storeProxy.off('before-set', beforeChange)
    //   storeProxy.off('after-set', afterChange)
    //   storeProxy.off('after-delete', afterChange)
    // }

    storeProxy.on('before-set', beforeChange)
    storeProxy.on('after-set', afterChange)
    storeProxy.on('after-delete', afterChange)

    const id = StoreBag.getStoreId(type, ...args)
    this.setStoreById(storeProxy.proxy, metadata, id)
    this.silentBag.setStoreById(store, metadata, id)
  }

  public async migrateStores (): Promise<void> {
    const { sharedMemoryManager: shm, keysManager } = this.locals
    for (const [id, prevStore] of Object.entries(this.stores)) {
      // Build new store options
      const metadata = this.getStoreMetadataById(id)
      const type = metadata.type
      let data
      if (type === 'public-settings') {
        continue
      }
      if (type === 'private-settings') {
        data = shm.memory.settings.private
      } else {
        data = await prevStore.getStore()
      }
      const args = metadata.args
      const oldOptions = _.pick(metadata.options, ['fileExtension', 'name']) as StoreOptions<StoreModel | PrivateSettings>
      // const filepath = getPath(this.ctx, this.locals, oldOptions)

      delete oldOptions.cwd
      let encryptionKey: KeyObject
      if (type === 'private-settings') {
        encryptionKey = await keysManager.computeSettingsKey()
      } else {
        const [, uuid] = oldOptions.name.split('.')
        encryptionKey = await keysManager.computeWalletKey(uuid)
      }
      const newOptions = { ...oldOptions, encryptionKey, defaults: data }

      // Remove old store
      this.deleteStoreById(id)

      // Create new store
      const [store, fixedOptions] = await this.builder.buildStore<StoreModels[typeof type]>(newOptions)
      this.sendStoreToBag(store, fixedOptions, type, ...args)
    }
  }

  // Cloud Sync
  public async updateUnsyncedChanges (
    unsyncedChanges: boolean,
    timestamp?: number
  ): Promise<void> {
    this.locals.sharedMemoryManager.update(mem => ({
      ...mem,
      settings: {
        ...mem.settings,
        public: {
          ...mem.settings.public,
          cloud: {
            ...mem.settings.public.cloud,
            timestamp: timestamp ?? mem.settings.public.cloud?.timestamp,
            unsyncedChanges
          }
        }
      }
    }))
  }

  public async bundleStores (): Promise<StoresBundle> {
    const { versionManager } = this.locals
    const storesBundle: StoresBundle = {
      version: versionManager.softwareVersion,
      stores: {}
    }
    for (const [storeId, store] of Object.entries(this.stores)) {
      const metadata = this.getStoreMetadataById(storeId)
      const type = metadata.type

      if (type === 'public-settings') {
        continue
      }

      const storeBundle: StoreBundleData = {
        metadata,
        data: await store.getStore()
      }
      storesBundle.stores[storeId] = storeBundle
    }
    return storesBundle
  }

  public async restoreStores (bundle: StoresBundle): Promise<void> {
    const { versionManager, sharedMemoryManager: shm, keysManager, walletFactory } = this.locals
    if (bundle.version !== versionManager.softwareVersion) {
      // TODO: Maybe raise exception
      return await this.locals.syncManager.conflict()
    }

    for (const [, storeBundle] of Object.entries(bundle.stores)) {
      const { type, args, options } = storeBundle.metadata
      if (!this.hasStore(type, ...args)) {
        // Create the store first
        let encryptionKey: KeyObject

        // TODO: Fix this better or juan will hate you for ever
        delete options.cwd
        if (type === 'private-settings') {
          encryptionKey = await keysManager.computeSettingsKey()
        } else {
          const [, uuid] = options.name.split('.')
          encryptionKey = await keysManager.computeWalletKey(uuid)
        }
        const [store, fixedOptions] = await this.builder.buildStore<StoreModels[typeof type]>({ ...options, encryptionKey })
        this.sendStoreToBag(store, fixedOptions, type, ...args)
      }

      const store = this.silentBag.getStore(type, ...args)
      await store.set(storeBundle.data)
    }

    // Refresh settings without notify store update
    const settingsId = StoreBag.getStoreId('private-settings')
    const settingsBundle = bundle.stores[settingsId] as StoreBundleData<'private-settings'>
    shm.update(mem => ({
      ...mem,
      settings: {
        ...mem.settings,
        private: settingsBundle.data
      }
    }), { modifiers: { 'no-settings-update': true } })

    // Refresh wallet data
    if (walletFactory.hasWalletSelected) {
      await walletFactory.refreshWalletData()
    }
  }

  public async silentStoreCredentials (credentials: Credentials): Promise<void> {
    const { sharedMemoryManager: shm } = this.locals
    const silentPrivateSettings = this.silentBag.getStore('private-settings')
    await silentPrivateSettings.set('cloud.credentials', credentials)
    shm.update(mem => ({
      ...mem,
      settings: {
        ...mem.settings,
        private: {
          ...mem.settings.private,
          cloud: {
            ...mem.settings.private.cloud,
            credentials
          }
        }
      }
    }), { modifiers: { 'no-settings-update': true } })
  }

  public async silentStoreVaultUrl (url: string): Promise<void> {
    const { sharedMemoryManager: shm } = this.locals
    const publicSettings = this.getStore('public-settings')
    await publicSettings.set('cloud.url', url)
    shm.update(mem => ({
      ...mem,
      settings: {
        ...mem.settings,
        public: {
          ...mem.settings.public,
          cloud: {
            unsyncedChanges: false,
            ...mem.settings.public.cloud,
            url: url
          }
        }
      }
    }), { modifiers: { 'no-settings-update': true } })
  }

  // Event handlers
  public async onStopCloudService (): Promise<void> {
    const { sharedMemoryManager: shm } = this.locals

    shm.update(mem => ({
      ...mem,
      cloudVaultData: {
        ...mem.cloudVaultData,
        state: VAULT_STATE.INITIALIZED
      },
      settings: {
        ...mem.settings,
        public: {
          ...mem.settings.public,
          cloud: {
            ...mem.settings.public.cloud,
            timestamp: undefined,
            unsyncedChanges: mem.settings.public.cloud?.unsyncedChanges ?? true
          }
        },
        private: {
          ...mem.settings.private,
          cloud: {
            ...mem.settings.private.cloud,
            credentials: undefined
          }
        }
      }
    }))
    const publicSettings = this.getStore('public-settings')
    await publicSettings.delete('cloud.credentials')
  }

  public async onCloudSynced (timestamp: number): Promise<void> {
    await this.updateUnsyncedChanges(false, timestamp)
  }

  protected async onBeforeChange <T extends StoreClass>(type: T, store: Store<StoreModels[T]>): Promise<void> {
    if (isEncryptedStore(type)) {
      this.updateUnsyncedChanges(true).catch((err) => { throw err })
    }
  }
}
