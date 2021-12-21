import { WalletPaths } from '@i3-market/wallet-desktop-openapi/types'

import { extractLocals } from '@wallet/main/locals'
import { asyncHandler } from './async-handler'

export const transactionDeploy = asyncHandler<never, WalletPaths.TransactionDeploy.Responses.$200, WalletPaths.TransactionDeploy.RequestBody>(async (req, res) => {
  const { walletFactory } = extractLocals(req.app)

  await walletFactory.wallet.transactionDeploy(req.body)
  res.sendStatus(200)
})
