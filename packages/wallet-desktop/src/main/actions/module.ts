import { Observable, Subscription } from 'rxjs'
import { Action } from '@wallet/lib'
import { Locals } from '../internal'
import { ActionHandlerBuilder, ActionHandler } from './action-handler'
import { Epic } from './epic'

export class Module {
  protected readonly handlerBuilders: ActionHandlerBuilder[]
  protected readonly epics: Epic[]
  protected subscriptions: Subscription[]

  constructor (opts: { handlersBuilders?: ActionHandlerBuilder[], epics?: Epic[] }) {
    this.handlerBuilders = opts.handlersBuilders ?? []
    this.epics = opts.epics ?? []
    this.subscriptions = []
  }

  bindReducer (
    reducer$: Observable<Action>,
    handlers: Map<string, ActionHandler>,
    locals: Locals
  ): void {
    // Bind handlers
    for (const hBuilder of this.handlerBuilders) {
      const handler = hBuilder(locals)
      handlers.set(handler.type, handler)
    }

    // this.subscriptions.push(handler(reducer$, locals)
    //   .subscribe((res) => {

    //   }, (err) => {
    //     if (err instanceof Error) {
    //       logger.error(err.message)
    //     } else {
    //       logger.error(err)
    //     }
    //   }, () => {
    //     logger.debug('Action handler completed??')
    //   }))
  }

  // TODO: We might need to implement this??
  unbindReducer (): void {
    throw new Error('Not implemented yet')
  }
}
