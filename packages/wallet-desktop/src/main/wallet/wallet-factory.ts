import { ProviderData, Wallet, WalletBuilder, WalletMetadata, DEFAULT_PROVIDERS_DATA, Descriptors } from '@i3m/base-wallet'
import { Provider, TaskDescription, WalletMetadataMap } from '@wallet/lib'
import {
  logger,
  Locals,
  FeatureManager,
  Feature,
  storeFeature,
  FeatureHandler,
  StartFeatureError,
  LabeledTaskHandler,
  WalletDesktopError,
  FeatureType,
  MainContext
} from '@wallet/main/internal'

import { InvalidWalletError, NoWalletSelectedError } from './errors'

interface WalletFeatureMap {
  [name: string]: Array<Feature<any>> | undefined
}

interface FeatureMap {
  [name: string]: FeatureHandler<any>
}

const featureMap: FeatureMap = {
  store: storeFeature
}

export class WalletFactory {
  protected _wallet: Wallet | undefined
  protected _walletName: string | undefined

  protected featuresByWallet: WalletFeatureMap

  static async initialize (ctx: MainContext, locals: Locals): Promise<WalletFactory> {
    return new WalletFactory(locals)
  }

  constructor (protected locals: Locals) {
    this._walletName = undefined
    this.featuresByWallet = {}
    this.bindRuntimeEvents()
  }

  protected bindRuntimeEvents (): void {
    const { runtimeManager } = this.locals
    runtimeManager.on('wallet-metadatas', async () => {
      await this.loadDefaultProviders()
      await this.loadWalletsMetadata()
    })

    runtimeManager.on('ui', async () => {
      await this.loadCurrentWallet()
    })
  }

  async loadDefaultProviders (): Promise<void> {
    const { sharedMemoryManager: shm } = this.locals
    shm.update((mem) => ({
      ...mem,
      defaultProviders: DEFAULT_PROVIDERS_DATA
    }))
  }

  async loadWalletsMetadata (): Promise<void> {
    const walletsMetadata: WalletMetadataMap = {}
    for (const walletPackage of this.walletPackages) {
      const packageJson = await import(`${walletPackage}/package.json`)
      logger.info(`Loaded metadata for wallet '${walletPackage}'`)

      // Store wallet metadata
      const walletMetadata: WalletMetadata = packageJson.walletMetadata
      walletsMetadata[walletPackage] = walletMetadata

      // Initialize features
      const features: Array<Feature<any>> = []
      for (const [name, featureArgs] of Object.entries(walletMetadata.features)) {
        features.push(FeatureManager.CreateFeature(featureMap[name], featureArgs))
      }
      this.featuresByWallet[walletPackage] = features
    }

    const { sharedMemoryManager } = this.locals
    sharedMemoryManager.update((mem) => ({
      ...mem,
      walletsMetadata
    }))
  }

  async loadCurrentWallet (): Promise<void> {
    const { sharedMemoryManager: shm } = this.locals
    const { wallet } = shm.memory.settings.private
    if (wallet.current === undefined) {
      logger.debug('No wallets stored into the configuration')
      return
    }
    logger.debug(`The current configuration has the following wallets: ${Object.keys(wallet.wallets).join(', ')}`)

    await this.changeWallet(wallet.current)
  }

  async buildWalletTask (walletName: string, task: LabeledTaskHandler): Promise<Wallet> {
    const { sharedMemoryManager: shm, featureContext, featureManager, dialog, toast } = this.locals
    const { wallet, providers } = shm.memory.settings.private
    const providersData = providers.reduce<Record<string, ProviderData>>(
      (prev, curr) => {
        prev[`did:ethr:${curr.network}`] = curr
        return prev
      }, { ...DEFAULT_PROVIDERS_DATA })

    const walletInfo = wallet.wallets[walletName]
    if (walletInfo === undefined) {
      throw new Error('Inconsistent data!')
    }

    try {
      // Init wallet features
      // Initialize all the features
      await featureManager.clearFeatures()
      const features = this.featuresByWallet[walletInfo.package]
      if (features !== undefined) {
        for (const feature of features) {
          featureManager.addFeature(feature)
        }
      }
      await featureManager.start()

      // Initialize wallet
      const walletMain: WalletBuilder<any> = (await import(walletInfo.package)).default
      const wallet = await walletMain({
        ...walletInfo.args,

        store: featureContext.store,
        toast,
        dialog,
        providersData
      })

      return wallet
    } catch (err) {
      // Start errors should be bypassed
      if (err instanceof StartFeatureError) {
        throw err
      }
      if (err instanceof Error) {
        logger.error(err.stack)
      } else {
        logger.error(err)
      }

      throw new InvalidWalletError(`Cannot load the wallet '${walletName}'`)
    }
  }

  providerSelect (providers: Provider[]): Descriptors<Provider> {
    const completeProviderList: Provider[] = [
      ...Object.values(DEFAULT_PROVIDERS_DATA).map((provider) => ({
        ...provider,
        name: provider.network
      })),
      ...providers
    ]
    return {
      type: 'select',
      message: 'Select a network',
      values: completeProviderList,
      getText (provider) {
        return provider.name
      }
    }
  }

  async buildWallet (walletName: string): Promise<Wallet> {
    const taskInfo: TaskDescription = {
      title: 'Build Wallet',
      details: `Creating wallet ${walletName}`
    }
    return await this.locals.taskManager.createTask('labeled', taskInfo, async (task) => {
      return await this.buildWalletTask(walletName, task)
    })
  }

  async deleteWallet (walletName: string): Promise<void> {
    const { sharedMemoryManager: shm, storeManager } = this.locals
    const { wallets, current } = shm.memory.settings.private.wallet

    const { [walletName]: walletInfo, ...newWallets } = wallets
    if (walletInfo === undefined) {
      throw new Error('Inconsistent data!')
    }

    // Create a floating feature manager
    const featureManager = new FeatureManager(this.locals)
    const features = this.featuresByWallet[walletInfo.package]
    if (features !== undefined) {
      for (const feature of features) {
        featureManager.addFeature(feature)
      }
    }
    await featureManager.delete(walletName)

    let currentWallet = current
    if (currentWallet === walletName) {
      currentWallet = undefined
    }

    storeManager.deleteStore('wallet', walletName)

    this.locals.sharedMemoryManager.update((mem) => ({
      ...mem,
      settings: {
        ...mem.settings,
        private: {
          ...mem.settings.private,
          wallet: {
            ...mem.settings.private.wallet,
            wallets: newWallets,
            current: currentWallet
          }
        }
      }
    }))
  }

  async changeWallet (walletName: string): Promise<void> {
    if (walletName === this._walletName) {
      return
    }

    logger.info(`Change wallet to ${walletName}`)
    const { apiManager } = this.locals

    // Stop API
    await apiManager.close()

    // Build the current wallet
    try {
      this._wallet = await this.buildWallet(walletName)
      this._walletName = walletName
    } catch (err) {
      this._wallet = undefined
      this._walletName = undefined
      console.trace(err)
      this.locals.toast.show({
        message: 'Wallet initialization',
        details: `Could not initialize the wallet '${walletName}'`,
        type: 'warning'
      })
      this.locals.sharedMemoryManager.update((mem) => ({
        ...mem,
        settings: {
          ...mem.settings,
          private: {
            ...mem.settings.private,
            wallet: {
              ...mem.settings.private.wallet,
              current: undefined
            }
          }
        }
      }))
      return
    }

    this.locals.toast.show({
      message: 'Wallet change',
      type: 'info',
      details: `Using wallet '${walletName}'`
    })

    await this.refreshWalletData()

    // Start API
    await apiManager.listen()
  }

  async refreshWalletData (): Promise<void> {
    const { sharedMemoryManager: shm } = this.locals

    // Setup the resource list inside shared memory
    const identities = await this.wallet.getIdentities()
    const resources = await this.wallet.getResources()
    shm.update((mem) => ({
      ...mem, identities, resources
    }))
  }

  getWalletFeatures <T>(walletPackage: string): Array<Feature<T>> {
    const features = this.featuresByWallet[walletPackage]
    if (features === undefined) {
      throw new WalletDesktopError('Wallet features not defined')
    }
    return features
  }

  getWalletFeature <T>(walletPackage: string, featureName: FeatureType): Feature<T> | undefined {
    const features = this.getWalletFeatures<T>(walletPackage)
    const feature = features.reduce<Feature<T> | undefined>((prev, curr) => {
      if (curr.handler.name === featureName) {
        return curr
      }
      return prev
    }, undefined)
    return feature
  }

  get walletNames (): string[] {
    return Object.keys(this.locals.sharedMemoryManager.memory.settings.private.wallet.wallets)
  }

  get walletPackages (): string[] {
    return this.locals.sharedMemoryManager.memory.settings.private.wallet.packages
  }

  get walletName (): string | undefined {
    return this._walletName
  }

  get wallet (): Wallet {
    if (this._wallet === undefined) {
      throw new NoWalletSelectedError('Wallet not select. Maybe you might initialize the wallet factory first.')
    }

    return this._wallet
  }

  get hasWalletSelected (): boolean {
    return this._wallet !== undefined
  }
}
