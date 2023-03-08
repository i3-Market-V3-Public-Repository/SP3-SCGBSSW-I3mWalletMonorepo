import _ from 'lodash'
import { EventEmitter } from 'events'
import { Store } from '../../app'
import { CanBePromise } from '../../utils'

/**
 * A class that implements a storage in RAM to be used by a wallet
 */
export class RamStore<T extends Record<string, any> = Record<string, unknown>> extends EventEmitter implements Store<T> {
  model: T
  constructor (protected defaultModel: T) {
    super()
    this.model = _.cloneDeep(defaultModel)
  }

  on (eventName: 'changed', listener: (changedAt: number) => void): this
  on (eventName: 'cleared', listener: (changedAt: number) => void): this
  on (eventName: string | symbol, listener: (...args: any[]) => void): this
  on (eventName: string | symbol, listener: (...args: any[]) => void): this {
    return super.on(eventName, listener)
  }

  emit (eventName: 'changed', changedAt: number): boolean
  emit (eventName: 'cleared', changedAt: number): boolean
  emit (eventName: string | symbol, ...args: any[]): boolean
  emit (eventName: string | symbol, ...args: any[]): boolean {
    return super.emit(eventName, ...args)
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
    this.emit('changed', Date.now())
  }

  has (key: string): CanBePromise<boolean> {
    return _.has(this.model, key)
  }

  delete (key: string): CanBePromise<void> {
    this.model = _.omit(this.model, key) as any
    this.emit('changed', Date.now())
  }

  clear (): CanBePromise<void> {
    this.model = _.cloneDeep(this.defaultModel)
    this.emit('cleared', Date.now())
  }

  getStore (): CanBePromise<T> {
    return this.model
  }

  getPath (): string {
    return 'RAM'
  }
}
