import _ from 'lodash'

import { Store, BaseWalletModel } from '../../app'
import { CanBePromise } from '../../utils'

/**
 * A class that implements a storage in RAM to be used by a wallet
 */
export class RamStore implements Store<BaseWalletModel> {
  model: BaseWalletModel
  constructor () {
    this.model = this.defaultModel()
  }

  private defaultModel (): BaseWalletModel {
    return {
      resources: {},
      identities: {}
    }
  }

  get (key: any, defaultValue?: any): any {
    return _.get(this.model, key, defaultValue)
  }

  set (key: string, value: unknown): CanBePromise<void>
  set (key: any, value: any): CanBePromise<void> {
    _.set(this.model, key, value)
  }

  has<Key extends 'accounts'>(key: Key): CanBePromise<boolean> {
    return _.has(this.model, key)
  }

  delete <Key extends 'accounts'>(key: Key): CanBePromise<void> {
    this.model = _.omit(this.model, key) as any
  }

  clear (): CanBePromise<void> {
    this.model = this.defaultModel()
  }
}
