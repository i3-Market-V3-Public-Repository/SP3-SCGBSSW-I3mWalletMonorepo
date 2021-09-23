import { WalletComponents } from './openapi'

export type WalletError = Error & WalletComponents.Schemas.ApiError

export * from './openapi'
