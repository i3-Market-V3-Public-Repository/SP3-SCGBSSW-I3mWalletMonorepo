import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { extractLocals } from '@wallet/main/locals'
import { asyncHandler } from './async-handler'

export const selectiveDisclosure = asyncHandler<WalletPaths.SelectiveDisclosure.PathParameters, WalletPaths.SelectiveDisclosure.Responses.$200>(async (req, res) => {
  const { walletFactory } = extractLocals(req.app)
  res.json(await walletFactory.wallet.selectiveDisclosure(req.params))
})
