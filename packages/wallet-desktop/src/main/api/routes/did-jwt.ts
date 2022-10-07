import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { didJwtVerifyAction } from '@wallet/lib'
import { extractLocals } from '@wallet/main/locals'
import { asyncHandler } from './async-handler'

export const didJwtVerify = asyncHandler<never, WalletPaths.DidJwtVerify.Responses.$200, WalletPaths.DidJwtVerify.RequestBody>(async (req, res) => {
  const { actionReducer } = extractLocals(req.app)
  await actionReducer.fromApi(req, res, didJwtVerifyAction.create({
    body: req.body
  }))
})
