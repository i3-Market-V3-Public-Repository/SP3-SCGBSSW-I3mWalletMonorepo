import { Store } from '@i3m/base-wallet'
import { VaultStorage } from '@i3m/cloud-vault-client'
import { KeyObject } from 'crypto'

import {
  createDefaultPrivateSettings,
  getObjectDifference, StoreSettings
} from '@wallet/lib'
import {
  fixPrivateSettings,
  fixPublicSettings,
  handleErrorSync,
  Locals,
  logger,
  MainContext,
  PublicSettingsOptions,
  softwareVersion,
  StoreFeatureOptions,
  StoreModel,
  WalletDesktopError
} from '@wallet/main/internal'
import { currentStoreType, StoreOptions } from './builders'
import { StoreOptionsBuilder } from './migration'
import { StoreBag } from './store-bag'
import { StoreBuilder } from './store-builder'
import { StoreBundleData, StoreMetadata, StoresBundle } from './store-bundle'
import { StoreClass, StoreClasses, StoreModels } from './store-class'
import { StoreProxy } from './store-proxy'

const DEFAULT_STORE_SETTINGS: StoreSettings = { type: 'electron-store' }

export class StoreManager extends StoreBag {
  builder: StoreBuilder
  silentBag: StoreBag

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

    runtimeManager.on('private-settings', async () => {
      // Load encrypted settings
      // task.setDetails('Migrating and loading encrypted stores')
      await this.loadPrivateSettings()
    })

    runtimeManager.on('fix-settings', async () => {
      // Fix setting files
      await fixPublicSettings(this.locals)
      await fixPrivateSettings(this.locals)
    }) 

    runtimeManager.on('wallet-stores', async () => {
      // Load encrypted settings
      // task.setDetails('Migrating and loading encrypted stores')
      await this.loadWalletStores()
    })
  }

  // Class utils
  public async loadPublicSettings (): Promise<void> {
    const options: PublicSettingsOptions = {
      defaults: { version: softwareVersion(this.locals) }
    }

    // NOTE: Public settings must always be not encrypted and using the electorn store.
    // This guarantees compatibilities with future versions!
    const [publicSettings, fixedOptions] = await this.builder.buildStore(options, 'electron-store')
    const publicMetadata: StoreMetadata<'public-settings'> = {
      type: 'public-settings',
      args: [],
      options: fixedOptions
    }
    // const f: StoreIdMetadata<'public-settings'> = ['public-settings']
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
    const { version, auth, cloud, store, enc, ...rest} = await publicSettings.getStore()

    await this.executeOptionsBuilders(async (migration) => ({
      defaults: Object.assign({}, createDefaultPrivateSettings(), rest),
      encryptionKey: await keysManager.computeSettingsKey(migration.encKeys),
      fileExtension: 'enc.json'
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

  //
  protected sendStoreToBag <T extends StoreClass> (
    store: Store<StoreModels[T]>,
    options: StoreOptions<StoreModels[T]>,
    type: T,
    ...args: StoreClasses[T]
  ): void  {
    const metadata: StoreMetadata<T> = { type, args, options }

    const storeProxy = new StoreProxy(store)
    const beforeChange = async (): Promise<void> => {
      await this.onBeforeChange(type, store)
    }
    const afterChange = async (): Promise<void> => {
      await this.onAfterChange(type, store)
    }
    const afterDelete = async (): Promise<void> => {
      storeProxy.off('before-set', beforeChange)
      storeProxy.off('after-set', afterChange)
      storeProxy.off('after-delete', afterDelete)
    }

    storeProxy.on('before-set', beforeChange)
    storeProxy.on('after-set', afterChange)
    storeProxy.on('after-delete', afterDelete)

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
  protected async bundleStores (): Promise<StoresBundle> {
    const { versionManager } = this.locals
    const storesBundle: StoresBundle = {
      version: versionManager.softwareVersion,
      stores: {}
    }
    for (const [storeId, store] of Object.entries(this.stores)) {
      // const idMetadata = StoreBag.deconstructId(storeId)
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

  public async uploadStores (force = false): Promise<void> {
    const { sharedMemoryManager: sh, cloudVaultManager } = this.locals
    if (sh.memory.settings.cloud === undefined) {
      return
    }

    const publicSettings = this.getStore('public-settings')
    const cloud = await publicSettings.get('cloud')

    const bundle = await this.bundleStores()
    const bundleJSON = JSON.stringify(bundle)
    const storage = Buffer.from(bundleJSON)

    const newTimestamp = await cloudVaultManager.updateStorage({
      storage, timestamp: cloud?.timestamp
    }, force)

    // Update timestamp
    await publicSettings.set('cloud', {
      timestamp: newTimestamp,
      unsyncedChanges: false
    })
  }

  public async restoreStoreBundle (vault: VaultStorage): Promise<void> {
    logger.debug('restore from cloud vault')
    const { storage } = vault
    const bundleJSON = storage.toString()
    const bundle = JSON.parse(bundleJSON) as StoresBundle

    const { versionManager, sharedMemoryManager: shm, keysManager } = this.locals
    if (bundle.version !== versionManager.softwareVersion) {
      // TODO: Handle version conflict!!
      return
    }

    for (const [, storeBundle] of Object.entries(bundle.stores)) {
      const { type, args, options } = storeBundle.metadata
      if (!this.hasStore(type, ...args)) {
        // Create the store first
        let encryptionKey: KeyObject
        if (type === 'private-settings') {
          encryptionKey = await keysManager.computeSettingsKey()
        } else {
          const [, uuid] = options.name.split('.')
          encryptionKey = await keysManager.computeWalletKey(uuid)
        }
        await this.executeOptions({ ...options, encryptionKey }, type, ...args)
      }

      const store = this.silentBag.getStore(type, ...args)
      await store.set(storeBundle.data)
    }

    const settingsId = StoreBag.getStoreId('private-settings')
    const settingsBundle = bundle.stores[settingsId] as StoreBundleData<'private-settings'>
    shm.update(mem => ({
      ...mem,
      settings: settingsBundle.data
    }), { reason: 'cloud-sync' })

    const publicSettings = this.getStore('public-settings')
    await publicSettings.set('cloud', {
      timestamp: vault.timestamp,
      unsyncedChanges: false
    })
  }

  // Events
  public async onStopCloudService (): Promise<void> {
    const { sharedMemoryManager: shm } = this.locals

    shm.update(mem => ({
      ...mem,
      settings: {
        ...mem.settings,
        cloud: undefined
      }
    }))
    const publicSettings = this.getStore('public-settings')
    await publicSettings.delete('cloud')
  }

  oldStores: any = {}
  protected async onBeforeChange (type: StoreClass, store: Store<any>): Promise<void> {
    if (isEncryptedStore(type)) {
      const storePath = store.getPath()
      let oldStore = this.oldStores[storePath]
      if (oldStore === undefined) {
        oldStore = {}
        this.stores[storePath]
      }
      const newStore = await store.getStore()
      console.log(getObjectDifference(oldStore, newStore))
      this.oldStores[storePath] = newStore
      const publicSettings = this.getStore('public-settings')
      await publicSettings.set('cloud.unsyncedChanges', true)
    }
  }

  protected async onAfterChange (type: StoreClass, store: Store<any>): Promise<void> {
    logger.debug(`The store has been changed ${store.getPath()}`)
    const { cloudVaultManager: cvm } = this.locals
    if (isEncryptedStore(type) && !cvm.isDisconnected) {
      await this.uploadStores().catch((err: Error) => {
        let fixedError = err
        if (!(err instanceof WalletDesktopError)) {
          console.trace(err)
          fixedError = new WalletDesktopError('Could not upload stores', {
            severity: 'error',
            message: 'Upload store error',
            details: `Could not upload store due to '${err.message}'`
          })
        }
        handleErrorSync(this.locals, fixedError)
      })
    }
  }
}

type EncryptedStoreClass = 'wallet' | 'private-settings'
function isEncryptedStore (type: StoreClass): type is EncryptedStoreClass {
  return type !== 'public-settings'
}
