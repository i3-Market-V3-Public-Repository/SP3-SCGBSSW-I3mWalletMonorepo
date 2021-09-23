import { BrowserWindow } from 'electron'
import { EventEmitter } from 'events'

import { SharedMemory, createDefaultSharedMemory } from '@wallet/lib'

export class SharedMemoryManager extends EventEmitter {
  private _memory: SharedMemory

  constructor (values?: Partial<SharedMemory>) {
    super()
    this._memory = createDefaultSharedMemory(values)
  }

  on (event: 'change', listener: (sharedMemory: SharedMemory, emitter: BrowserWindow | undefined) => void): this
  on (event: string | symbol, listener: (...args: any[]) => void): this {
    return super.on(event, listener)
  }

  once (event: 'change', listener: (mem: SharedMemory) => void): this
  once (event: string | symbol, listener: (...args: any[]) => void): this {
    return super.once(event, listener)
  }

  emit (event: 'change', sharedMemory: SharedMemory, emitter?: BrowserWindow): boolean
  emit (event: string | symbol, ...args: any[]): boolean {
    return super.emit(event, ...args)
  }

  update (cb: (sharedMemory: SharedMemory) => SharedMemory, emitter?: BrowserWindow): void
  update (sharedMemory: SharedMemory, emitter?: BrowserWindow): void
  update (modifier: any, emitter?: BrowserWindow): void {
    let sharedMemory: SharedMemory | undefined
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

    this.emit('change', this._memory, emitter)
  }

  get memory (): SharedMemory {
    return this._memory
  }
}
