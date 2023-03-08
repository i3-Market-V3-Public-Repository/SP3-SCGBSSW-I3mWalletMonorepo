import { Module } from '../module'
import { walletProtocolPairing } from './handlers'

export const connectModule = new Module({
  handlersBuilders: [
    walletProtocolPairing
  ]
})
