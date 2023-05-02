import { BrowserWindow } from 'electron'
import { EventEmitter } from 'events'

import { SharedMemory, createDefaultSharedMemory } from '@wallet/lib'
import { Locals } from '../locals'
import { bindWithDialog, bindWithSettings, bindWithTray, bindWithWalletFactory, bindWithWindowManager } from './bindings'
import { MainContext } from '../models'

export interface ChangeEvent {
  curr: SharedMemory
  prev: SharedMemory

  // Optionals
  ctx?: {
    emitter?: BrowserWindow
    modifiers?: {
      'no-settings-update'?: boolean
    }
  }
}

export interface SharedMemoryManagerEvents {
  change: ChangeEvent
}
export type SharedMemoryManagerEventNames = keyof SharedMemoryManagerEvents

export class SharedMemoryManager extends EventEmitter {
  private _memory: SharedMemory

  static async initialize (ctx: MainContext, locals: Locals): Promise<SharedMemoryManager> {
    return new SharedMemoryManager(ctx, locals)
  }

  constructor (protected ctx: MainContext, protected locals: Locals, values?: Partial<SharedMemory>) {
    super()
    this._memory = createDefaultSharedMemory(values)
    this.bindRuntimeEvents()
  }

  bindRuntimeEvents (): void {
    const { runtimeManager } = this.locals
    // Before auth
    runtimeManager.on('start', async () => {
      await bindWithDialog(this.locals)
      await bindWithTray(this.locals)
      await bindWithWindowManager(this.locals)
    })

    runtimeManager.on('after-migration', async () => {
      await bindWithSettings(this.ctx, this.locals)
      await bindWithWalletFactory(this.locals)
    })
  }

  on <T extends SharedMemoryManagerEventNames>(event: T, listener: (ev: SharedMemoryManagerEvents[T]) => void): this
  on (event: string | symbol, listener: (...args: any[]) => void): this {
    return super.on(event, listener)
  }

  once <T extends SharedMemoryManagerEventNames>(event: T, listener: (ev: SharedMemoryManagerEvents[T]) => void): this
  once (event: string | symbol, listener: (...args: any[]) => void): this {
    return super.once(event, listener)
  }

  emit <T extends SharedMemoryManagerEventNames>(event: T, ev: SharedMemoryManagerEvents[T]): boolean
  emit (event: string | symbol, ...args: any[]): boolean {
    return super.emit(event, ...args)
  }

  update (cb: (sharedMemory: SharedMemory) => SharedMemory, ctx?: ChangeEvent['ctx']): void
  update (sharedMemory: SharedMemory, ctx?: ChangeEvent['ctx']): void
  update (modifier: any, ctx?: ChangeEvent['ctx']): void {
    let sharedMemory: SharedMemory | undefined
    const oldSharedMemory = this._memory
    if (typeof modifier === 'function') {
      sharedMemory = modifier(this._memory)
    } else {
      sharedMemory = modifier
    }

    if (sharedMemory === undefined) {
      throw new Error('Shared memory update cannot be undefined')
    } else if (sharedMemory === this._memory) {
      throw new Error('Shared memory update must create a new object')
    }
    this._memory = sharedMemory

    this.emit('change', {
      curr: this._memory,
      prev: oldSharedMemory,
      ctx
    })
  }

  get memory (): SharedMemory {
    return this._memory
  }
}
