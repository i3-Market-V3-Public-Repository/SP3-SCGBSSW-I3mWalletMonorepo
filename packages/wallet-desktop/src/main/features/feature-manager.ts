
import { Locals, logger } from '@wallet/main/internal'
import { FeatureHandler } from './feature-handler'

export interface Feature<T> {
  handler: FeatureHandler<T>
  opts?: T
}

// FIXME: The feature management is too messy.
// It is difficult to understand how to use it because it is too dependent to the WalletFactory.
export class FeatureManager {
  features: Map<string, Feature<any>>
  constructor (protected locals: Locals) {
    this.features = new Map()
  }

  static CreateFeature<T> (handler: FeatureHandler<T>, opts?: T): Feature<T> {
    return { handler, opts }
  }

  addFeature<T> (feature: Feature<T>): void {
    const name = feature.handler.name
    if (this.features.has(name)) {
      logger.error(`Feature with name '${name}' already set`)
      return
    }

    this.features.set(name, feature)
  }

  async getWallet (walletName?: string): Promise<string> {
    if (walletName !== undefined) {
      return walletName
    }

    const walletSettings = await this.locals.settings.get('wallet')
    if (walletSettings.current === undefined) {
      throw new Error('Wallet settings is undefined')
    }

    return walletSettings.current
  }

  async clearFeatures (walletName?: string): Promise<void> {
    for (const [, feature] of this.features) {
      if (feature.handler.stop !== undefined) {
        const wallet = await this.getWallet(walletName)
        await feature.handler.stop(wallet, feature.opts, this.locals)
      }
    }
    this.features.clear()
  }

  async start (walletName?: string): Promise<void> {
    for (const [, feature] of this.features) {
      if (feature.handler.start !== undefined) {
        const wallet = await this.getWallet(walletName)
        await feature.handler.start(wallet, feature.opts, this.locals)
      }
    }
  }

  async delete (walletName?: string): Promise<void> {
    for (const [, feature] of this.features) {
      if (feature.handler.delete !== undefined) {
        const wallet = await this.getWallet(walletName)
        await feature.handler.delete(wallet, feature.opts, this.locals)
      }
    }
  }
}
