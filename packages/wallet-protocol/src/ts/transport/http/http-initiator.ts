import { constants, format, MasterKey } from '../../internal'
import { InitiatorTransport } from '../initiator-transport'
import { Request } from '../request'

export interface HttpRequest {
  url: string
  init: RequestInit
}

export type HttpResponse = Response

export class HttpInitiatorTransport extends InitiatorTransport<HttpRequest, HttpResponse> {
  buildRpcUrl (port: number): string {
    return `http://${this.opts.host}:${port}/${constants.RPC_URL_PATH}`
  }

  async sendRequest<T extends Request> (request: Request): Promise<T> {
    if (this.connString === undefined) {
      throw new Error('cannot connect to the rpc yet: port missing')
    }

    const port = this.connString.extractPort()
    const rpcUrl = this.buildRpcUrl(port)
    const resp = await fetch(rpcUrl, {
      method: 'POST',
      body: JSON.stringify(request)
    })
    const body: T = await resp.json()

    return body
  }

  async send (masterKey: MasterKey, code: Uint8Array, req: HttpRequest): Promise<HttpResponse> {
    const headers = new Headers()
    headers.append('Authorization', format.u8Arr2Utf(code))

    const message = format.utf2U8Arr(JSON.stringify(req))
    const ciphertext = await masterKey.encrypt(message)
    const rpcUrl = this.buildRpcUrl(29170)

    const resp = await fetch(rpcUrl, {
      method: 'POST',
      headers: headers,
      body: format.u8Arr2Base64(ciphertext)
    })

    return new Proxy<HttpResponse>(resp, {
      get: (resp, p) => {
        switch (p) {
          case 'json':
            return async () => {
              const ciphertextBase64 = await resp.text()
              const ciphertext = format.base642U8Arr(ciphertextBase64)
              const jsonBuffer = await masterKey.decrypt(ciphertext)
              const json = format.u8Arr2Utf(jsonBuffer)

              return JSON.parse(json)
            }

          default:
            return (resp as any)[p]
        }
      }
    })
  }
}
