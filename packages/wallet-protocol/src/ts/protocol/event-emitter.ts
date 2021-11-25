
export class EventEmitter {
  events: Record<string, Function[]>

  constructor () {
    this.events = {}
  }

  on (event: string, cb: Function): this {
    if (this.events[event] === undefined) {
      this.events[event] = []
    }

    this.events[event].push(cb)
    return this
  }

  emit (event: string, ...data: any): boolean {
    const eventCbs = this.events[event]
    if (eventCbs !== undefined) {
      eventCbs.forEach(eventCb => eventCb(...data))
      return true
    }
    return false
  }
}
