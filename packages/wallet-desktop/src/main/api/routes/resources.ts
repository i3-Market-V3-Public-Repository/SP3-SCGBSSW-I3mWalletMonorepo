import { RequestHandler } from 'express'
import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { WindowManager, extractLocals } from '@wallet/main/internal'
import { asyncHandler } from './async-handler'

export const resourceList = asyncHandler<never, WalletPaths.ResourceList.Responses.$200, never, never>(async (req, res) => {
  const { walletFactory } = extractLocals(req.app)
  const resp = await walletFactory.wallet.resourceList()
  res.json(resp)
})

export const resourceCreate = asyncHandler<never, WalletPaths.ResourceCreate.Responses.$201, WalletPaths.ResourceCreate.RequestBody>(async (req, res) => {
  const { walletFactory, sharedMemoryManager } = extractLocals(req.app)
  const resp = await walletFactory.wallet.resourceCreate(req.body)

  // Update state
  const resources = await walletFactory.wallet.getResources()
  sharedMemoryManager.update((mem) => ({ ...mem, resources }))

  res.status(201).json(resp)
})

export const resourceDelete: RequestHandler = (req, res) => {
  const windowManager: WindowManager = req.app.locals.windowManager
  windowManager.openSignWindow('hello')
  console.log('Hello world')
  res.send('Hello world')
}

export const resourceRead: RequestHandler = (req, res) => {
  const windowManager: WindowManager = req.app.locals.windowManager
  windowManager.openSignWindow('hello')
  console.log('Hello world')
  res.send('Hello world')
}

export const resourceUpdate: RequestHandler = (req, res) => {
  const windowManager: WindowManager = req.app.locals.windowManager
  windowManager.openSignWindow('hello')
  console.log('Hello world')
  res.send('Hello world')
}
