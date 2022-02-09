import { Session, HttpInitiatorTransport } from '@i3m/wallet-protocol'
import { DisclosureApi, IdentitiesApi, ResourcesApi, TransactionApi } from './models'
import { ApiExecutor, Params, Body, ApiMethod } from './types'

export class WalletApi implements ApiExecutor {
  public identities: IdentitiesApi
  public transaction: TransactionApi
  public resources: ResourcesApi
  public disclosure: DisclosureApi

  constructor (protected session: Session<HttpInitiatorTransport>) {
    this.identities = new IdentitiesApi(this)
    this.transaction = new TransactionApi(this)
    this.resources = new ResourcesApi(this)
    this.disclosure = new DisclosureApi(this)
  }

  public async executeQuery<T>(api: ApiMethod, pathParams: Params, queryParams: Params, bodyObject: Body): Promise<T> {
    let queryParamsString = ''
    if (queryParams !== undefined) {
      queryParamsString = '?' + Object
        .keys(queryParams)
        .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`)
        .join('&')
    }

    let body
    if (bodyObject !== undefined) {
      body = JSON.stringify(bodyObject)
    }

    let url = api.path + queryParamsString
    if (pathParams !== undefined) {
      for (const [key, value] of Object.entries(pathParams)) {
        url = url.replace(`{${key}}`, value)
      }
    }

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
}
