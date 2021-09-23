import { Action, ActionRequest } from '@wallet/lib'
import { useOutput } from './output'

type ActionDispatcher = (action: Action) => void

export const useAction = (): ActionDispatcher => {
  const output$ = useOutput()
  return (action) => {
    const actionRequest: ActionRequest = {
      type: 'action', action
    }
    output$.next(actionRequest)
  }
}
