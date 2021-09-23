import { Action } from '@wallet/lib'

export class ActionError extends Error {
  constructor (msg: string, public action: Action, public status?: number) {
    super(msg)
  }
}
