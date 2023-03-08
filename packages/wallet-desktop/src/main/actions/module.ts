import { Observable, Subscription } from 'rxjs'
import { Action } from '@wallet/lib'
import { Locals } from '../internal'
import { ActionHandlerBuilder, ActionHandler } from './action-handler'
import { Epic, NextAction } from './epic'

export class Module {
  protected readonly handlerBuilders: ActionHandlerBuilder[]
  protected readonly epics: Epic[]
  protected subscriptions: Subscription[]

  constructor (opts: { handlersBuilders?: ActionHandlerBuilder[], epics?: Epic[] }) {
    this.handlerBuilders = opts.handlersBuilders ?? []
    this.epics = opts.epics ?? []
    this.subscriptions = []
  }

  bind (
    action$: Observable<Action>,
    handlers: Map<string, ActionHandler>,
    locals: Locals,
    next: NextAction
  ): void {
    // Bind handlers
    for (const hBuilder of this.handlerBuilders) {
      const handler = hBuilder(locals)
      handlers.set(handler.type, handler)
    }

    for (const eBuilder of this.epics) {
      this.subscriptions.push(eBuilder(action$, locals, next))
    }
  }

  unbind (handlers: Map<string, ActionHandler>, locals: Locals): void {
    // TODO: Could be more eficient but I think this will never be used...
    for (const hBuilder of this.handlerBuilders) {
      const handler = hBuilder(locals)
      handlers.delete(handler.type)
    }

    for (const subscription of this.subscriptions) {
      subscription.unsubscribe()
    }
    throw new Error('Not implemented yet')
  }
}
