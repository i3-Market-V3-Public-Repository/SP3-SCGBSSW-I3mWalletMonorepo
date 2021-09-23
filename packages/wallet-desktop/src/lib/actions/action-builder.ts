import { Action } from './action'

export interface ActionBuilder<A extends Action = Action, R = any> {
  type: A['type']
  action?: A
  response?: R
  payload?: A['payload']
  create: (...args: any) => A
}

export type GetAction<B extends ActionBuilder> =
  Exclude<B['action'], undefined>

export type GetResponse<B extends ActionBuilder> =
  Exclude<B['response'], undefined>

export type GetPayload<B extends ActionBuilder> =
  Exclude<B['payload'], undefined>

export type GetType<B extends ActionBuilder> = B['type']
