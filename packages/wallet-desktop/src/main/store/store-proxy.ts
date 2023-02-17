import { Store } from '@i3m/base-wallet'

export interface StoreEvent<E extends string, A extends []> {
  event: E
  args: A
}

export type StoreEvents =
  StoreEvent<'before-set', []> |
  StoreEvent<'after-set', []>

export type StoreEventTypes = StoreEvents['event']
export type StoreEventFor<E extends StoreEventTypes> = StoreEvents & { event: E }
export type StoreEventCallback<E extends StoreEventTypes = StoreEventTypes> =
  (...args: StoreEventFor<E>['args']) => Promise<void>

export class StoreProxy<T extends Record<string, any> = Record<string, unknown>> {
  eventListeners: Record<string, StoreEventCallback[] | undefined>

  constructor (protected store: Store<T>) {
    this.eventListeners = {}
  }

  get proxy (): Store<T> {
    const store = this.store
    return {
      async clear () {
        // @ts-expect-error
        return await store.clear(...arguments)
      },
      async get () {
        // @ts-expect-error
        return await store.get(...arguments)
      },
      async set () {
        // @ts-expect-error
        return await store.set(...arguments)
      },
      async has () {
        // @ts-expect-error
        return await store.has(...arguments)
      },
      async delete () {
        // @ts-expect-error
        return await store.delete(...arguments)
      },

      async getStore () {
        // @ts-expect-error
        return await store.getStore(...arguments)
      },
      getPath () {
        // @ts-expect-error
        return store.getPath(...arguments)
      },

      // Events

      emit () {
        // @ts-expect-error
        return store.emit(...arguments)
      },
      on () {
        // @ts-expect-error
        return store.on(...arguments)
      }
    }
  }

  on <E extends StoreEventTypes>(event: E, cb: StoreEventCallback<E>): void {
    let listeners = this.eventListeners[event]
    if (listeners === undefined) {
      listeners = []
      this.eventListeners[event] = listeners
    }
    listeners.push(cb)
  }

  off <E extends StoreEventTypes>(event: E, cb: StoreEventCallback<E>): void {
    const listeners = this.eventListeners[event]
    if (listeners === undefined) {
      return
    }
    this.eventListeners[event] = listeners.filter(listener => listener !== cb)
  }

  async emit <E extends StoreEventTypes>(event: E, ...args: StoreEventFor<E>['args']): Promise<void> {
    const listeners = this.eventListeners[event]
    if (listeners === undefined) {
      return
    }
    for (const listener of listeners) {
      await listener(...args)
    }
  }
}
