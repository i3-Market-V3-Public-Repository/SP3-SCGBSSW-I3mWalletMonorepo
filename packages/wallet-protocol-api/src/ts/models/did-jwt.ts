import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { ApiExecutor } from '../types'

export class DidJwtApi {
  constructor (protected api: ApiExecutor) { }

  async verify (body: WalletPaths.DidJwtVerify.RequestBody): Promise<WalletPaths.DidJwtVerify.Responses.$200> {
    return await this.api.executeQuery({
      path: '/did-jwt/verify',
      method: 'POST'
    }, undefined, undefined, body)
  }
}
