import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { createIdentityAction, signAction } from '@wallet/lib'
import { extractLocals } from '@wallet/main/locals'
import { asyncHandler } from './async-handler'

export const identityList = asyncHandler<never, WalletPaths.IdentityList.Responses.$200, never, WalletPaths.IdentityList.QueryParameters>(async (req, res) => {
  const { walletFactory } = extractLocals(req.app)
  const response = await walletFactory.wallet.identityList(req.query)
  res.json(response)
})

export const identitySelect = asyncHandler<never, WalletPaths.IdentitySelect.Responses.$200, never, WalletPaths.IdentitySelect.QueryParameters>(async (req, res) => {
  const { walletFactory } = extractLocals(req.app)
  const response = await walletFactory.wallet.identitySelect(req.query)
  res.json(response)
})

export const identityCreate = asyncHandler<never, WalletPaths.IdentityCreate.Responses.$201, WalletPaths.IdentityCreate.RequestBody>(async (req, res) => {
  const { actionReducer } = extractLocals(req.app)
  await actionReducer.fromApi(req, res, createIdentityAction.create(req.body))
})

export const identitySign = asyncHandler<WalletPaths.IdentitySign.PathParameters, WalletPaths.IdentitySign.Responses.$200, WalletPaths.IdentitySign.RequestBody>(async (req, res) => {
  const { actionReducer } = extractLocals(req.app)
  await actionReducer.fromApi(req, res, signAction.create({
    signer: req.params,
    body: req.body
  }))
})

export const identityInfo = asyncHandler<WalletPaths.IdentityInfo.PathParameters, WalletPaths.IdentityInfo.Responses.$200>(async (req, res) => {
  const { walletFactory } = extractLocals(req.app)
  const response = await walletFactory.wallet.identityInfo(req.params)
  res.json(response)
})

export const identityDeployTransaction = asyncHandler<WalletPaths.IdentityDeployTransaction.PathParameters, WalletPaths.IdentityDeployTransaction.Responses.$200, WalletPaths.IdentityDeployTransaction.RequestBody>(async (req, res) => {
  const { walletFactory } = extractLocals(req.app)
  const response = await walletFactory.wallet.identityDeployTransaction(req.query, req.body)
  res.json(response)
})
