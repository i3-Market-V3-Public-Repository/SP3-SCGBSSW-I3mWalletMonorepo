import {
  closeToastAction as actionBuilder
} from '@wallet/lib'
import { ActionHandlerBuilder } from '../action-handler'

export const closeToast: ActionHandlerBuilder<typeof actionBuilder> = (
  locals
) => {
  return {
    type: actionBuilder.type,
    async handle (action) {
      const { toast } = locals
      const toastId = action.payload
      toast.close(toastId)

      return { response: undefined }
    }
  }
}
