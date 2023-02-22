
export type AsyncEventType<T> = T extends Record<infer R, any[]> ? R : never
export type AsyncEventCallback<E extends any[]> = (...ev: E) => Promise<void>
export type AsyncEventMap<T extends Record<string, any>> = {
  [E in keyof T]?: Array<AsyncEventCallback<T[E]>>
}

export class AsyncEventHandler<T extends Record<P, any[]>, P extends keyof T = keyof T> {
  protected listeners: AsyncEventMap<T>
  constructor () {
    this.listeners = {}
  }

  on <E extends keyof T>(event: E, listener: AsyncEventCallback<T[E]>): void {
    let listeners = this.listeners[event]
    if (listeners === undefined) {
      listeners = []
      this.listeners[event] = listeners
    }

    listeners.push(listener)
  }

  off <E extends keyof T>(event: E, listener: AsyncEventCallback<T[E]>): void {
    const listeners = this.listeners[event]
    if (listeners === undefined) {
      return
    }
    this.listeners[event] = listeners.filter(l => l !== listener)
  }

  async emit <E extends keyof T>(evType: E, ...args: T[E]): Promise<void> {
    const listeners = this.listeners[evType]
    if (listeners === undefined) {
      return
    }

    for (const listener of listeners) {
      await listener(...args)
    }
  }
}
