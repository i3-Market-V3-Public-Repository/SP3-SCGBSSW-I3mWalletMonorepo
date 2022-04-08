import http from 'http'

import { constants, format } from '../../internal'
import { ResponderTransport, ResponderOptions } from '../responder-transport'
import { HttpResponse } from './http-response'
import { HttpRequest } from './http-initiator'

export interface HttpResponderOptions extends ResponderOptions {
  rpcUrl: string
}

export class HttpResponderTransport extends ResponderTransport<http.IncomingMessage, never> {
  readonly rpcUrl: string
  protected listeners: http.RequestListener[] = []

  constructor (opts?: Partial<HttpResponderOptions>) {
    super(opts)
    this.rpcUrl = opts?.rpcUrl ?? `/${constants.RPC_URL_PATH}`
  }

  protected async readRequestBody (req: http.IncomingMessage): Promise<string> {
    const buffers = []
    for await (const chunk of req) {
      buffers.push(chunk)
    }

    return Buffer.concat(buffers).toString()
  }

  protected async dispatchProtocolMessage (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (!this.isPairing) {
      throw new Error('not in pairing mode')
    }

    const data = await this.readRequestBody(req)
    const reqBody = JSON.parse(data)
    this.rpcSubject.next({ req: reqBody, res: new HttpResponse(res) })
  }

  protected async dispatchEncryptedMessage (
    req: http.IncomingMessage,
    res: http.ServerResponse,
    authentication: string
  ): Promise<void> {
    const code = format.utf2U8Arr(authentication)
    const masterKey = await this.opts.codeGenerator.getMasterKey(code)

    const ciphertextBase64 = await this.readRequestBody(req)
    const ciphertext = format.base642U8Arr(ciphertextBase64)
    const message = await masterKey.decrypt(ciphertext)
    const messageJson = format.u8Arr2Utf(message)
    const body: HttpRequest = JSON.parse(messageJson)
    let innerBody: any = {}
    const init: RequestInit = body.init ?? {}
    if (init.body !== undefined && init.body !== '') {
      innerBody = JSON.parse(init.body as string)
    }

    const headers = Object
      .entries(init.headers ?? {})
      .reduce((h, [key, value]) => {
        h[key.toLocaleLowerCase()] = value
        return h
      }, req.headers)

    const reqProxy = new Proxy<http.IncomingMessage>(req, {
      get (target, p) {
        switch (p) {
          case 'url':
            return body.url

          case 'method':
            return init.method

          case 'headers':
            return headers

          case '_body':
            return true

          case 'body':
            return innerBody

          case 'walletProtocol':
            return true

          default:
            return (target as any)[p]
        }
      }
    })

    // TODO: Implement this in a better way??
    res.end = new Proxy<http.ServerResponse['end']>(res.end, {
      apply: (target: Function, thisArg, argsArray) => {
        const statusCode = thisArg.statusCode === undefined ? 500 : thisArg.statusCode
        if (statusCode >= 200 && statusCode < 300) {
          const chunk = argsArray[0]
          const send = async (): Promise<void> => {
            let buffer: Uint8Array
            if (typeof chunk === 'string') {
              buffer = format.utf2U8Arr(chunk)
            } else if (chunk instanceof Buffer) {
              buffer = chunk
            } else {
              throw new Error('cannot manage this chunk...')
            }
            const ciphertext = await masterKey.encrypt(buffer)
            const ciphertextBase64 = format.u8Arr2Base64(ciphertext)
            res.setHeader('Content-Length', ciphertextBase64.length)
            target.call(thisArg, ciphertextBase64, ...argsArray)
          }

          send().catch(err => { console.error(err) })
        } else {
          target.call(thisArg, ...argsArray)
        }
      }
    })

    await this.callListeners(reqProxy, res)
  }

  async dispatchRequest (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (req.url === this.rpcUrl) {
      if (req.method !== 'POST') {
        throw new Error('method must be POST')
      }
      if (req.headers.authorization !== undefined) {
        return await this.dispatchEncryptedMessage(req, res, req.headers.authorization)
      } else {
        return await this.dispatchProtocolMessage(req, res)
      }
    } else {
      await this.callListeners(req, res)
    }
  }

  private async callListeners (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    for (const listener of this.listeners) {
      listener(req, res)
    }
  }

  use (listener: http.RequestListener): void {
    this.listeners.push(listener)
  }
}
