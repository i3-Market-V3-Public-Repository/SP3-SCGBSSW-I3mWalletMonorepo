import { Module } from '../module'
import { walletProtocolPairing } from './wallet-protocol-pairing.handler'

export const connectModule = new Module({
  handlersBuilders: [
    walletProtocolPairing
  ]
})
