import { dialog, SaveDialogOptions } from 'electron'
import * as fs from 'fs'

import { Resource } from '@i3m/base-wallet'
import {
  importResourceAction
} from '@wallet/lib'
import { ActionHandlerBuilder } from '@wallet/main/internal'

export const importResource: ActionHandlerBuilder<typeof importResourceAction> = (
  locals
) => {
  return {
    type: importResourceAction.type,
    async handle (action) {
      const mainWindow = locals.windowManager.getWindow('Main')
      const dialogOptions: SaveDialogOptions = {
        title: 'Import resource...'
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

      let resource: Resource
      try {
        resource = JSON.parse(fs.readFileSync(resourcePath).toString('utf-8'))
      } catch (ex) {
        locals.toast.show({
          message: 'Could not import',
          type: 'warning',
          details: 'Invalid file format'
        })
        return { response: undefined }
      }

      if (!['VerifiableCredential', 'Contract', 'Object'].includes(resource.type)) {
        locals.toast.show({
          message: 'Could not import',
          type: 'warning',
          details: 'Invalid file format'
        })
        return { response: undefined }
      }

      if (action.payload !== undefined && action.payload !== resource.identity) {
        locals.toast.show({
          message: 'Could not import',
          type: 'warning',
          details: 'This resource is not for the provided identity'
        })
        return { response: undefined }
      }

      const { walletFactory, sharedMemoryManager } = locals

      // Verify wallet
      if (!walletFactory.hasWalletSelected) {
        locals.toast.show({
          message: 'Wallet not selected',
          details: 'You must select a wallet before creating identities',
          type: 'warning'
        })
        return { response: undefined, status: 500 }
      }
      await walletFactory.wallet.resourceCreate(resource)

      // Update state
      const resources = await walletFactory.wallet.getResources()
      sharedMemoryManager.update((mem) => ({ ...mem, resources }))

      return { response: undefined }
    }
  }
}
