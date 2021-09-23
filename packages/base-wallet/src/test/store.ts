import _ from 'lodash'

import { Store, BaseWalletModel } from '../app'
import { CanBePromise } from '../utils'

export class TestStore implements Store<BaseWalletModel> {
  model: BaseWalletModel
  constructor () {
    this.model = this.defaultModel()
  }

  private defaultModel (): BaseWalletModel {
    return {
      accounts: {},
      resources: {},
      identities: {}
    }
  }

  get<Key extends 'accounts'>(key: Key): CanBePromise<Partial<BaseWalletModel>[Key]>;
  get<Key extends 'accounts'>(key: Key, defaultValue: Required<BaseWalletModel>[Key]): CanBePromise<Required<BaseWalletModel>[Key]>;
  get (key: any, defaultValue?: any): any {
    return _.get(this.model, key, defaultValue)
  }

  set<Key extends 'accounts'>(key: Key, value: BaseWalletModel[Key]): CanBePromise<void>;
  set (key: string, value: unknown): CanBePromise<void>;
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
