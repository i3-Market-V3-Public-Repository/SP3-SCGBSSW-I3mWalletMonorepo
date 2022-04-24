import { dialog, SaveDialogOptions } from 'electron'
import * as fs from 'fs'
import {
  exportResourceAction
} from '@wallet/lib'
import { ActionHandlerBuilder } from '../action-handler'

export const exportResource: ActionHandlerBuilder<typeof exportResourceAction> = (
  locals
) => {
  return {
    type: exportResourceAction.type,
    async handle (action) {
      const { sharedMemoryManager } = locals
      const sharedMemory = sharedMemoryManager.memory
      const resource = sharedMemory.resources[action.payload]
      if (resource === undefined) {
        locals.toast.show({
          message: 'Could not export',
          type: 'warning',
          details: 'Resource not found'
        })
        return { response: undefined, status: 400 }
      }

      const mainWindow = locals.windowManager.getWindow('Main')
      const dialogOptions: SaveDialogOptions = {
        title: 'Export resource...',
        defaultPath: `${resource.id}.resource.json`
      }

      let resourcePath: string | undefined
      if (mainWindow !== undefined) {
        resourcePath = dialog.showSaveDialogSync(mainWindow, dialogOptions)
      } else {
        resourcePath = dialog.showSaveDialogSync(dialogOptions)
      }

      if (resourcePath === undefined) {
        return { response: undefined }
      }

      fs.writeFileSync(resourcePath, JSON.stringify(resource, null, 2))
      return { response: undefined }
    }
  }
}
