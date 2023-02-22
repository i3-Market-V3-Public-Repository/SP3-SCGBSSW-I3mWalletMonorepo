import { Store } from '@i3m/base-wallet'

import {
  createDefaultPrivateSettings,
  PrivateSettings,
  StoreSettings
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
import { currentStoreType } from './builders'
import { StoreOptionsBuilder } from './migration'
import { StoreBag } from './store-bag'
import { StoreBuilder } from './store-builder'
import { StoreBundleData, StoreMetadata, StoresBundle } from './store-bundle'
import { StoreClass, StoreClasses } from './store-class'
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
    const publicSettings = await this.builder.buildStore(options, 'electron-store')
    this.setStore(publicSettings, 'public-settings')

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
    const publicSettingsValues = await publicSettings.getStore()

    await this.executeOptionsBuilders(async (migration) => ({
      defaults: Object.assign({}, createDefaultPrivateSettings(), publicSettingsValues),
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
  // (): Store<StoreModels[T]> {
  protected async executeOptionsBuilders <T extends StoreClass>(
    optionsBuilder: StoreOptionsBuilder<any>,
    type: T,
    ...args: StoreClasses[T]
  ): Promise<void> {
    const store = await this.builder.buildOptionsBuilder(optionsBuilder)

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
    this.setStoreById(storeProxy.proxy, id)
    this.silentBag.setStoreById(store, id)
  }

  // Cloud Sync

  protected async bundleStores (): Promise<StoresBundle> {
    const { versionManager } = this.locals
    const storesBundle: StoresBundle = {
      version: versionManager.softwareVersion,
      stores: {}
    }
    for (const [storeId, store] of Object.entries(this.stores)) {
      const idMetadata = StoreBag.deconstructId(storeId)
      const type = idMetadata[0]

      if (type === 'public-settings') {
        continue
      }

      const metadata: StoreMetadata = {
        idMetadata
      }

      const storeBundle: StoreBundleData = {
        metadata,
        data: await store.getStore()
      }
      storesBundle.stores[storeId] = storeBundle
    }
    return storesBundle
  }

  protected async uploadStores (): Promise<void> {
    const { sharedMemoryManager: sh, cloudVaultManager } = this.locals
    if (sh.memory.settings.cloud === undefined) {
      return
    }

    const publicSettings = this.getStore('public-settings')
    const cloud = await publicSettings.get('cloud')

    const bundle = await this.bundleStores()
    const bundleJSON = JSON.stringify(bundle)
    const buffer = Buffer.from(bundleJSON)

    const newTimestamp = await cloudVaultManager.updateStorage(buffer, cloud?.timestamp)

    // Update timestamp
    await publicSettings.set('cloud', {
      timestamp: newTimestamp,
      unsyncedChanges: false
    })
  }

  public async restoreStoreBundle (buffer: Buffer): Promise<void> {
    const bundleJSON = buffer.toString()
    const bundle = JSON.parse(bundleJSON) as StoresBundle

    const { versionManager, sharedMemoryManager: sh } = this.locals
    if (bundle.version !== versionManager.softwareVersion) {
      // TODO: Handle version conflict!!
      return
    }

    for (const [, storeBundle] of Object.entries(bundle.stores)) {
      const { idMetadata } = storeBundle.metadata
      const type = idMetadata[0]
      if (!this.hasStore(...idMetadata)) {
        // Create the store first
      }

      const store = this.silentBag.getStore(...idMetadata)
      await store.set(storeBundle.data)

      if (type === 'private-settings') {
        sh.update(mem => ({
          ...mem,
          settings: storeBundle.data as PrivateSettings
        }), { reason: 'cloud-sync' })
      }
    }
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

  protected async onBeforeChange (type: StoreClass, store: Store<any>): Promise<void> {
    console.log('Store changed!', store.getPath())

    if (isEncryptedStore(type)) {
      const publicSettings = this.getStore('public-settings')
      await publicSettings.set('cloud.unsyncedChanges', true)
    }
  }

  protected async onAfterChange (type: StoreClass, store: Store<any>): Promise<void> {
    logger.debug(`The store has been changed ${store.getPath()}`)
    const { cloudVaultManager: cvm } = this.locals
    if (isEncryptedStore(type) && cvm.isConnected) {
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
