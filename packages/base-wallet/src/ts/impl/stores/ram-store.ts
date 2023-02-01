import _ from 'lodash'

import { Store } from '../../app'
import { CanBePromise } from '../../utils'

/**
 * A class that implements a storage in RAM to be used by a wallet
 */
export class RamStore<T extends Record<string, any> = Record<string, unknown>> implements Store<T> {
  model: T
  constructor (protected defaultModel: T) {
    this.model = _.cloneDeep(defaultModel)
  }

  get (key: any, defaultValue?: any): any {
    return _.get(this.model, key, defaultValue)
  }

  set (keyOrStore?: any, value?: any): CanBePromise<void> {
    if (value === undefined) {
      Object.assign({}, this.model, keyOrStore)
      return
    }
    _.set(this.model, keyOrStore, value)
  }

  has<Key extends 'accounts'>(key: Key): CanBePromise<boolean> {
    return _.has(this.model, key)
  }

  delete <Key extends 'accounts'>(key: Key): CanBePromise<void> {
    this.model = _.omit(this.model, key) as any
  }

  clear (): CanBePromise<void> {
    this.model = _.cloneDeep(this.defaultModel)
  }

  getStore (): CanBePromise<T> {
    return this.model
  }

  getPath (): string {
    return 'RAM'
  }
}
