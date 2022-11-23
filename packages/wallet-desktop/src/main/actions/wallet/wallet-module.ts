import { Module } from '../module'
import { createWallet } from './create-wallet.handler'
import { selectWallet } from './select-wallet.handler'
import { deleteWallet } from './delete-wallet.handler'
import { createIdentity } from './create-identity.handler'
import { deleteIdentity } from './delete-identity.handler'
import { importResource } from './import-resource.handler'
import { exportResource } from './export-resource.handler'
import { deleteResource } from './delete-resource.handler'
import { sign } from './sign.handler'
import { verifyJWT } from './verify-jwt.handler'
import { callWalletFunction } from './call-wallet-function.handler'
import { getProviderinfo } from './get-providerinfo.handler'

export const walletModule = new Module({
  handlersBuilders: [
    createWallet,
    selectWallet,
    deleteWallet,
    createIdentity,
    deleteIdentity,
    importResource,
    exportResource,
    deleteResource,
    sign,
    verifyJWT,
    callWalletFunction,
    getProviderinfo
  ]
})
