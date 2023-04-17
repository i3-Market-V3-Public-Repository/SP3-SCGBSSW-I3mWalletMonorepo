import http from 'http'

import { constants, format, MasterKey } from '../../internal'
import { InitiatorTransport } from '../initiator-transport'
import { Request } from '../request'

export interface HttpRequest {
  url: string
  init?: RequestInit
}

export interface HttpResponse {
  status: number
  body: string
}
type HttpType = typeof http

function checkIfIPv6 (str: string): boolean {
  const regexExp = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/gi

  return regexExp.test(str)
}

export class HttpInitiatorTransport extends InitiatorTransport<HttpRequest, HttpResponse> {
  async baseSend (port: number, httpReq: RequestInit): Promise<HttpResponse> {
    if (IS_BROWSER) {
      const host = checkIfIPv6(this.opts.host) ? `[${this.opts.host}]` : this.opts.host
      const rpcUrl = `http://${host}:${port}/${constants.RPC_URL_PATH}`
      const resp = await fetch(rpcUrl, httpReq)
      const body = await resp.text()

      return {
        status: resp.status,
        body
      }
    } else {
      const http: HttpType = await import('http')
      const resp = await new Promise<HttpResponse>(resolve => {
        const postData = httpReq.body as string
        const req = http.request({
          path: `/${constants.RPC_URL_PATH}`,
          host: this.opts.host,
          port,
          method: httpReq.method ?? 'POST',
          headers: {
            ...httpReq.headers as any,
            'Content-Length': Buffer.byteLength(postData)
          }
        }, (res) => {
          let data = ''
          res.on('data', (chunk: string) => {
            data += chunk
          })
          res.on('end', () => {
            resolve({
              status: res.statusCode ?? 200,
              body: data
            })
          })
        })

        req.write(postData)
        req.end()
      })

      return resp
    }
  }

  async sendRequest<T extends Request> (request: Request): Promise<T> {
    if (this.connString === undefined) {
      throw new Error('cannot connect to the rpc yet: port missing')
    }

    const port = this.connString.extractPort()

    const resp = await this.baseSend(port, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(request)
    })

    return JSON.parse(resp.body)
  }

  async send (masterKey: MasterKey, code: Uint8Array, req: HttpRequest): Promise<HttpResponse> {
    const message = format.utf2U8Arr(JSON.stringify(req))
    const ciphertext = await masterKey.encrypt(message)

    const resp = await this.baseSend(masterKey.port, {
      method: 'POST',
      headers: {
        Authorization: format.u8Arr2Utf(code)
      },
      body: format.u8Arr2Base64(ciphertext)
    })

    // Decrypt body
    if (resp.status <= 300 && resp.status >= 200) {
      const bodyCiphertext = format.base642U8Arr(resp.body)
      const jsonBuffer = await masterKey.decrypt(bodyCiphertext)
      resp.body = format.u8Arr2Utf(jsonBuffer)
    }

    return resp
  }
}
