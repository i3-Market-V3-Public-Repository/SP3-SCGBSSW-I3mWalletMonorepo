import { Observable } from 'rxjs'

import { Action } from '@wallet/lib'
import { Locals } from '../internal'

export type Epic<T extends Action = Action, S extends Action = Action> =
  (obs$: Observable<T>, locals: Locals) => Observable<S>
