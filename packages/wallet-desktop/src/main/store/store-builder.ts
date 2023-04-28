import _ from 'lodash'

import { StoreSettings, WalletInfo } from '@wallet/lib'
import { EncryptionKeys, Locals, logger, MainContext, StoreFeatureOptions, WalletStoreOptions } from '@wallet/main/internal'

import { Store } from '@i3m/base-wallet'
import { getPath, loadStoreBuilder, StoreOptions } from './builders'

export class StoreBuilder {
  defaultStoreSettings: StoreSettings

  constructor (protected ctx: MainContext, protected locals: Locals) {
    this.defaultStoreSettings = { type: 'electron-store' }
  }

  public async buildWalletStoreOptions (wallet: WalletInfo, opts: StoreFeatureOptions | undefined, encKeys?: EncryptionKeys): Promise<WalletStoreOptions> {
    const { keysManager } = this.locals
    const name = _.get(opts, 'name', 'wallet')
    const storePath = _.get(opts, 'storePath', this.ctx.args.config)
    const encryptionEnabled: boolean = _.get(opts, 'encryption.enabled', false)
    const storeId = wallet.store

    const storeOpts: WalletStoreOptions = {
      defaults: {
        start: new Date(),
        identities: {},
        resources: {}
      },
      name: `${name}.${storeId}`,
      cwd: storePath,
      fileExtension: encryptionEnabled ? 'enc.json' : 'json'
    }

    if (encryptionEnabled) {
      storeOpts.encryptionKey = await keysManager.computeWalletKey(wallet.store, encKeys)
    }

    return storeOpts
  }

  public async buildStore <T extends Record<string, any> = Record<string, unknown>>(options?: Partial<StoreOptions<T>>): Promise<[store: Store<T>, options: StoreOptions<T>]> {
    const fixedOptions = Object.assign({}, {
      cwd: this.ctx.args.config,
      fileExtension: 'json',
      name: 'config',
      storeType: this.defaultStoreSettings.type
    }, options)
    const builder = loadStoreBuilder<T>(fixedOptions.storeType)
    const storePath = getPath(this.ctx, this.locals, options)

    if (fixedOptions.onBeforeBuild !== undefined) {
      await fixedOptions.onBeforeBuild(storePath, fixedOptions)
    }

    // TODO: Check if the format is corret. If not fix corrupted data
    logger.debug(`Loading store on '${storePath}'`)
    return [await builder.build(this.ctx, this.locals, fixedOptions), fixedOptions]
  }
}
