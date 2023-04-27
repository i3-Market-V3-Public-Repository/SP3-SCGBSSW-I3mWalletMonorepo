import { Store } from '@i3m/base-wallet'
import { KeyObject } from 'crypto'
import { existsSync } from 'fs'
import fs from 'fs/promises'

import {
  createDefaultPrivateSettings,
  Credentials, storeChangedAction, StoreClass,
  StoreClasses, StoreModel, StoreModels, StoreSettings
} from '@wallet/lib'
import {
  fixPrivateSettings,
  fixPublicSettings, handleErrorCatch, isEncryptedStore,
  Locals, logger, MainContext,
  PublicSettingsOptions,
  softwareVersion,
  StoreFeatureOptions,
  WalletDesktopError
} from '@wallet/main/internal'

import { currentStoreType, StoreOptions } from './builders'
import { StoreOptionsBuilder } from './migration'
import { StoreBag } from './store-bag'
import { StoreBuilder } from './store-builder'
import { StoreBundleData, StoreMetadata, StoresBundle } from './store-bundle'
import { StoreProxy } from './store-proxy'
import { VAULT_STATE } from '@i3m/cloud-vault-client'

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

    const [publicSettings, fixedOptions] = await this.builder.buildStore({ ...options, storeType: 'electron-store' })
    const publicMetadata: StoreMetadata<'public-settings'> = {
      type: 'public-settings',
      args: [],
      options: fixedOptions
    }

    // NOTE: Public settings must always be not encrypted and using the electorn store.
    // This guarantees compatibilities with future versions!
    this.setStore(publicSettings, publicMetadata, 'public-settings')

    // Migrate to last store type
    this.builder.storeInfo = await publicSettings.get('store') ?? DEFAULT_STORE_SETTINGS
    if (this.builder.storeInfo.type !== currentStoreType) {
      const { storeMigrationProxy } = this.ctx
      const { runtimeManager } = this.locals

      storeMigrationProxy.from.storeType = this.builder.storeInfo.type
      storeMigrationProxy.to.storeType = currentStoreType
      runtimeManager.on('migration', async (to) => {
        this.builder.storeInfo.type = currentStoreType
        await publicSettings.set('store', { type: currentStoreType })
      })
    }
  }

  public async loadPrivateSettings (): Promise<void> {
    const { keysManager } = this.locals
    const publicSettings = this.getStore('public-settings')
    const { version, auth, cloud, store, enc, ...rest } = await publicSettings.getStore()
    const options: Partial<StoreOptions<any>> = {
      fileExtension: 'enc.json'
    }

    await this.executeOptionsBuilders(async (migration) => ({
      defaults: Object.assign({}, createDefaultPrivateSettings(), rest),
      encryptionKey: await keysManager.computeSettingsKey(migration.encKeys),
      onBeforeBuild: async (storePath, opts) => {
        if (migration.direction === 'from') {
          await this.handleStoreBackup(storePath, opts)
        }
      },
      ...options
    }), 'private-settings')
  }

  public async loadWalletStores (): Promise<void> {
    const { walletFactory } = this.locals
    const privateSettings = this.getStore('private-settings')
    const walletSettings = await privateSettings.get('wallet')
    const walletOptionsBuilders = Object
      .values(walletSettings.wallets)
      .map((wallet) => ({
        wallet,
        storeFeature: walletFactory.getWalletFeature<StoreFeatureOptions>(wallet.package, 'store')
      }))
      .filter(({ storeFeature }) => storeFeature !== undefined)
      .map(({ wallet, storeFeature }) => {
        const optionBuilder: StoreOptionsBuilder<any> = async (migration) => await this.builder.buildWalletStoreOptions(wallet, storeFeature?.opts, migration.encKeys)

        return {
          walletName: wallet.name,
          optionBuilder
        }
      })

    for (const { walletName, optionBuilder } of walletOptionsBuilders) {
      await this.executeOptionsBuilders(optionBuilder, 'wallet', walletName)
    }
  }

  // Store Bag methods
  public async buildWalletStore (walletName: string): Promise<void> {
    const { walletFactory } = this.locals
    const privateSettings = this.getStore('private-settings')
    const walletSettings = await privateSettings.get('wallet')
    const wallet = walletSettings?.wallets[walletName]
    if (wallet === undefined) {
      throw new WalletDesktopError('Wallet metadata not found')
    }
    const storeFeature = walletFactory.getWalletFeature<StoreFeatureOptions>(wallet.package, 'store')
    const builder: StoreOptionsBuilder<StoreModel> = async (migration) => {
      return await this.builder.buildWalletStoreOptions(wallet, storeFeature?.opts, migration.encKeys)
    }

    await this.executeOptionsBuilders(builder, 'wallet', walletName)
  }

  protected sendStoreToBag <T extends StoreClass> (
    store: Store<StoreModels[T]>,
    options: StoreOptions<StoreModels[T]>,
    type: T,
    ...args: StoreClasses[T]
  ): void {
    const { actionReducer } = this.locals
    const metadata: StoreMetadata<T> = { type, args, options }

    const storeProxy = new StoreProxy(store)
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

  protected async executeOptions <T extends StoreClass>(
    options: StoreOptions<StoreModels[T]>,
    type: T,
    ...args: StoreClasses[T]
  ): Promise<void> {
    const [store, fixedOptions] = await this.builder.buildStore(options)
    this.sendStoreToBag(store, fixedOptions, type, ...args)
  }

  protected async executeOptionsBuilders <T extends StoreClass>(
    optionsBuilder: StoreOptionsBuilder<any>,
    type: T,
    ...args: StoreClasses[T]
  ): Promise<void> {
    const [store, options] = await this.builder.buildOptionsBuilder(optionsBuilder)
    this.sendStoreToBag(store, options, type, ...args)
  }

  // Cloud Sync
  public async updateUnsyncedChanges (
    unsyncedChanges: boolean,
    timestamp?: number
  ): Promise<void> {
    this.locals.sharedMemoryManager.update(mem => ({
      ...mem,
      cloudVaultData: {
        ...mem.cloudVaultData,
        unsyncedChanges
      },
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
    const { to } = this.ctx.storeMigrationProxy

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

        // TODO: Fix this better or juan kills you
        delete options.cwd
        if (type === 'private-settings') {
          encryptionKey = await keysManager.computeSettingsKey(to.encKeys)
        } else {
          const [, uuid] = options.name.split('.')
          encryptionKey = await keysManager.computeWalletKey(uuid, to.encKeys)
        }
        await this.executeOptions({ ...options, encryptionKey, storeType: to.storeType }, type, ...args)
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

  // Event handlers
  public async onCloudLogin (credentials: Credentials): Promise<void> {
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
