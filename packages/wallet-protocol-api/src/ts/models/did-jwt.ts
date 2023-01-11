import { WalletComponents, WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { ApiExecutor } from '../types'

export class DidJwtApi {
  constructor (protected api: ApiExecutor) { }

  async verify (body: WalletPaths.DidJwtVerify.RequestBody): Promise<WalletPaths.DidJwtVerify.Responses.$200> {
    const response = (await this.api.executeQuery({
      path: '/did-jwt/verify',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, undefined, undefined, body))
    if ((response as WalletComponents.Schemas.ApiError).code !== undefined) {
      throw new Error(`${(response as WalletComponents.Schemas.ApiError).code}: ${(response as WalletComponents.Schemas.ApiError).message}`)
    }
    return response as WalletPaths.DidJwtVerify.Responses.$200
  }
}
