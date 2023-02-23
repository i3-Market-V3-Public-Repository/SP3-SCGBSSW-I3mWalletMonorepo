import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { getProviderinfoAction } from '@wallet/lib'
import { extractLocals } from '@wallet/main/locals'
import { asyncHandler } from './async-handler'

export const providerinfoGet = asyncHandler<never, WalletPaths.ProviderinfoGet.Responses.$200, never>(async (req, res) => {
  const { actionReducer } = extractLocals(req.app)
  await actionReducer.fromApi(req, res, getProviderinfoAction.create(undefined))
})
