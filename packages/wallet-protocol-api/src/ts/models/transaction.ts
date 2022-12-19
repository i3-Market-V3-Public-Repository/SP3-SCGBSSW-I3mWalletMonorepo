import { WalletComponents, WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { ApiExecutor } from '../types'

export class TransactionApi {
  constructor (protected api: ApiExecutor) { }

  async deploy (body: WalletPaths.TransactionDeploy.RequestBody): Promise<WalletPaths.TransactionDeploy.Responses.$200> {
    const response = await this.api.executeQuery({
      path: '/transaction/deploy',
      method: 'POST'
    }, undefined, undefined, body)
    if ((response as WalletComponents.Schemas.ApiError).code !== undefined) {
      throw new Error(`${(response as WalletComponents.Schemas.ApiError).code}: ${(response as WalletComponents.Schemas.ApiError).message}`)
    }
    return response as WalletPaths.TransactionDeploy.Responses.$200
  }
}
