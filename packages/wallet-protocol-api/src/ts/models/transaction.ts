import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { ApiExecutor } from '../types'

export class TransactionApi {
  constructor (protected api: ApiExecutor) { }

  async deploy (body: WalletPaths.TransactionDeploy.RequestBody): Promise<WalletPaths.TransactionDeploy.Responses.$200> {
    return await this.api.executeQuery({
      path: '/transaction/deploy',
      method: 'POST'
    }, undefined, undefined, body)
  }
}
