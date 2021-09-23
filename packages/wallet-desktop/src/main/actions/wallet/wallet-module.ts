import { Module } from '../module'
import { createWallet } from './create-wallet.handler'
import { selectWallet } from './select-wallet.handler'
import { createIdentity } from './create-identity.handler'
import { deleteIdentity } from './delete-identity.handler'

export const walletModule = new Module({
  handlersBuilders: [
    createWallet,
    selectWallet,
    createIdentity,
    deleteIdentity
  ]
})
