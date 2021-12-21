import { Session, HttpInitiatorTransport } from '@i3m/wallet-protocol'
import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'
import { ApiMethod, GET_IDENTITIES } from './api-method'

type Params = Record<string, string> | undefined
type Body = any

export class WalletApi {
  constructor (protected session: Session<HttpInitiatorTransport>) {}

  private async executeQuery<T>(api: ApiMethod<T>, queryParams: Params, bodyObject: Body): Promise<T> {
    let queryParamsString = ''
    if (queryParams !== undefined) {
      queryParamsString = '?' + Object
        .keys(queryParams)
        .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`)
        .join('&')
    }

    let body
    if (bodyObject !== undefined) {
      body = JSON.parse(bodyObject)
    }

    const url = api.path + queryParamsString
    const resp = await this.session.send({
      url,
      init: {
        headers: api.headers,
        method: api.method,
        body
      }
    })
    return JSON.parse(resp.body)
  }

  async getIdentites (queryParams?: WalletPaths.IdentityList.QueryParameters): Promise<WalletPaths.IdentityList.Responses.$200> {
    return await this.executeQuery(GET_IDENTITIES, queryParams as Params, undefined)
  }
}
