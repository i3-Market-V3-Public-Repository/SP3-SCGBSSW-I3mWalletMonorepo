import { Locals } from '@wallet/main/internal'

export const bindWithDialog = async (locals: Locals): Promise<void> => {
  const { sharedMemoryManager, dialog: dialogManager } = locals

  sharedMemoryManager.on('change', ({ curr: mem }) => {
    const dialogId = mem.dialogs.current
    if (dialogId === undefined) {
      return
    }

    const { [dialogId]: dialog, ...otherDialogs } = mem.dialogs.data
    if (dialog === undefined || !('response' in dialog)) {
      return
    }

    locals.sharedMemoryManager.update((mem) => ({
      ...mem,
      dialogs: {
        ...mem.dialogs,
        current: dialogManager.dialogQueue.shift(),
        data: otherDialogs
      }
    }))

    const resolver = dialogManager.resolvers.get(dialog.id)
    if (resolver !== undefined) {
      dialogManager.resolvers.delete(dialog.id)
      resolver(dialog.response)
    } else {
      // TODO: Handle error
      throw new Error('Dialog not found')
    }
  })
}
