import { Store } from '@i3m/base-wallet'
import { existsSync, rmSync } from 'fs'

import { WalletDesktopError } from '@wallet/main/internal'
import { StoreClass, StoreClasses, StoreModels } from './store-class'

export class StoreBag {
  stores: Record<string, Store<any>>

  constructor () {
    this.stores = {}
  }

  //

  static getStoreId <T extends StoreClass>(type: T, ...args: StoreClasses[T]): string {
    if (type === 'wallet') {
      return `wallet$$${args[0]}`
    } else {
      return `${type}$$`
    }
  }

  static deconstructId <T extends StoreClass>(storeId: string): [type: T, ...args: StoreClasses[T]] {
    const regex = /([^$]+)\$\$(.+)?/
    const match = storeId.match(regex)
    if (match === null) {
      throw new WalletDesktopError(`Invalid store id '${storeId}'`)
    }

    const [, ...storeData] = match
    return storeData as any
  }

  //

  public getStoreById <T extends StoreClass>(storeId: string): Store<StoreModels[T]> {
    const store = this.stores[storeId]
    if (store === undefined) {
      throw new WalletDesktopError(`The store '${storeId}' is not initialized yet.`)
    }
    return store
  }

  public setStoreById <T extends StoreClass>(store: Store<StoreModels[T]>, storeId: string): void {
    if (this.stores[storeId] !== undefined) {
      throw new WalletDesktopError(`The store '${storeId}' is already initialized.`)
    }
    this.stores[storeId] = store
  }

  public deleteStoreById (storeId: string): void {
    const store = this.getStoreById(storeId)
    delete this.stores[storeId] // eslint-disable-line @typescript-eslint/no-dynamic-delete

    const path = store.getPath()
    if (existsSync(path)) {
      rmSync(path)
    }
  }

  //

  public getStore <T extends StoreClass>(type: T, ...args: StoreClasses[T]): Store<StoreModels[T]> {
    const storeId = StoreBag.getStoreId(type, ...args)
    return this.getStoreById(storeId)
  }

  public setStore <T extends StoreClass>(store: Store<StoreModels[T]>, type: T, ...args: StoreClasses[T]): void {
    const storeId = StoreBag.getStoreId(type, ...args)
    this.setStoreById(store, storeId)
  }

  public hasStore <T extends StoreClass>(type: T, ...args: StoreClasses[T]): boolean {
    const storeId = StoreBag.getStoreId(type, ...args)
    return this.stores[storeId] !== undefined
  }

  public deleteStore <T extends StoreClass>(type: T, ...args: StoreClasses[T]): void {
    const storeId = StoreBag.getStoreId(type, ...args)
    this.deleteStoreById(storeId)
  }
}
