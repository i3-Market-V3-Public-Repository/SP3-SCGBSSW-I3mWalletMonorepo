
import { FeatureContext, Locals, logger, MainContext, WalletDesktopError } from '@wallet/main/internal'
import { FeatureHandler } from './feature-handler'
import { WalletInfo } from '@wallet/lib'

export interface Feature<T> {
  handler: FeatureHandler<T>
  opts?: T
}

export class FeatureManager {
  features: Map<string, Feature<any>>
  walletInfo?: WalletInfo

  static async initialize (ctx: MainContext, locals: Locals): Promise<FeatureManager> {
    return new FeatureManager(locals)
  }

  static async initializeContext (ctx: MainContext, locals: Locals): Promise<FeatureContext> {
    return {}
  }

  constructor (protected locals: Locals) {
    this.features = new Map()
  }

  static CreateFeature<T> (handler: FeatureHandler<T>, opts?: T): Feature<T> {
    return { handler, opts }
  }

  get hasFeatures (): boolean {
    return this.walletInfo !== undefined
  }

  addFeature<T> (feature: Feature<T>): void {
    const name = feature.handler.name
    if (this.features.has(name)) {
      logger.error(`Feature with name '${name}' already set`)
      return
    }

    this.features.set(name, feature)
  }

  async loadWalletFeatures (walletInfo: WalletInfo): Promise<void> {
    if (this.walletInfo !== undefined) {
      throw new WalletDesktopError('wallet features already loaded', {
        message: 'Wallet Feautes',
        details: 'Could not load wallet features. You must clean previous features first.',
        severity: 'error'
      })
    }

    const { walletFactory } = this.locals

    const oldFeatures = this.features
    const oldWalletInfo = this.walletInfo

    this.walletInfo = walletInfo
    this.features = new Map()

    try {
      const features = walletFactory.getWalletFeatures(walletInfo.package)
      if (features !== undefined) {
        for (const feature of features) {
          this.addFeature(feature)
        }
      }
    } catch (err) {
      this.features = oldFeatures
      this.walletInfo = oldWalletInfo

      throw err
    }
  }

  // Wallet feature events
  async start (): Promise<void> {
    if (this.walletInfo === undefined) {
      throw new WalletDesktopError('cannot start features', {
        message: 'Wallet Features',
        details: 'Cannot start features without initializing the feature manager',
        severity: 'error'
      })
    }

    for (const [, feature] of this.features) {
      if (feature.handler.start !== undefined) {
        await feature.handler.start(this.walletInfo, feature.opts, this.locals)
      }
    }
  }

  async clearFeatures (): Promise<void> {
    if (this.walletInfo === undefined) {
      return
    }

    for (const [, feature] of this.features) {
      if (feature.handler.stop !== undefined) {
        await feature.handler.stop(this.walletInfo, feature.opts, this.locals)
      }
    }
    this.features.clear()
    this.walletInfo = undefined
  }

  async delete (): Promise<void> {
    if (this.walletInfo === undefined) {
      throw new WalletDesktopError('cannot start features', {
        message: 'Wallet Features',
        details: 'Cannot start features without initializing the feature manager',
        severity: 'error'
      })
    }

    for (const [, feature] of this.features) {
      if (feature.handler.delete !== undefined) {
        await feature.handler.delete(this.walletInfo, feature.opts, this.locals)
      }
    }
  }
}
