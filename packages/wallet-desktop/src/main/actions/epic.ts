import { Observable, OperatorFunction, Subscription } from 'rxjs'

import { Action, ActionBuilder } from '@wallet/lib'
import { Locals } from '../internal'
import { filter } from 'rxjs/operators'

export type NextAction = (action: Action) => void

export type Epic<T extends Action = Action> =
  (obs$: Observable<T>, locals: Locals, next: NextAction) => Subscription

type GetAction<T extends ActionBuilder> = T extends ActionBuilder<infer R> ? R : never

export const filterAction = <T extends ActionBuilder>(actionBuilder: T): OperatorFunction<Action, GetAction<T>> => {
  return (action$: Observable<Action>) => action$.pipe(
    filter(p => p.type === actionBuilder.type)
  ) as Observable<GetAction<T>>
}
