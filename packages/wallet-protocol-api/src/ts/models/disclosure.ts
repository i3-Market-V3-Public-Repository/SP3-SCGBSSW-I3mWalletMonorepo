import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { ApiExecutor } from '../types'

export class DisclosureApi {
  constructor (protected api: ApiExecutor) { }

  async disclose (pathParams: WalletPaths.SelectiveDisclosure.PathParameters): Promise<WalletPaths.SelectiveDisclosure.Responses.$200> {
    return await this.api.executeQuery({
      path: '/disclosure',
      method: 'GET'
    }, pathParams as any, undefined, undefined)
  }
}
