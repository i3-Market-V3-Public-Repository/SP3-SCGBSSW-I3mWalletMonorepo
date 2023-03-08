import { Module } from '../module'
import { callWalletFunction, createIdentity, createWallet, deleteIdentity, deleteResource, deleteWallet, exportResource, getProviderinfo, importResource, selectWallet, sign, verifyJWT } from './handlers'

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
