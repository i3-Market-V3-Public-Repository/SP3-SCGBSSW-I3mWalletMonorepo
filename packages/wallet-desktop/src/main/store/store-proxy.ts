import { Store } from '@i3m/base-wallet'
import { AsyncEventHandler } from '../events'

// export interface StoreEvent<E extends string, A extends []> {
//   event: E
//   args: A
// }

// export type StoreEvents =
//   StoreEvent<'before-set', []> |
//   StoreEvent<'after-set', []> |
//   StoreEvent<'after-delete', []>

// export type StoreEventTypes = StoreEvents['event']
// export type StoreEventFor<E extends StoreEventTypes> = StoreEvents & { event: E }
// export type StoreEventCallback<E extends StoreEventTypes = StoreEventTypes> =
//   (...args: StoreEventFor<E>['args']) => Promise<void>

interface StoreEvents {
  'before-set': []
  'after-set': []
  'after-delete': []
}

export class StoreProxyBuilder<T extends Record<string, any> = Record<string, unknown>> extends AsyncEventHandler<StoreEvents> {
  constructor (protected store: Store<T>) {
    super()
    this.emit = this.emit.bind(this)
  }

  get proxy (): Store<T> {
    const store = this.store
    const emit = this.emit

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
        await emit('before-set')

        // @ts-expect-error
        const res = await store.set(...arguments)

        await emit('after-set')

        return res
      },
      async has () {
        // @ts-expect-error
        return await store.has(...arguments)
      },
      async delete () {
        // @ts-expect-error
        const res = await store.delete(...arguments)

        await emit('after-delete')
        return res
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
}
