import {
  showToastAction as actionBuilder
} from '@wallet/lib'
import { ActionHandlerBuilder } from '@wallet/main/internal'

export const showToast: ActionHandlerBuilder<typeof actionBuilder> = (
  locals
) => {
  return {
    type: actionBuilder.type,
    async handle (action) {
      const { toast } = locals
      const toastOptions = action.payload
      toast.show(toastOptions)

      return { response: undefined }
    }
  }
}
