import http from 'http'
import { WalletProtocol, Subject, format, ProtocolPKEData, constants, AuthData, PKEData, ProtocolAuthData } from '../../internal'
import { ResponderTransport, ResponderOptions } from '../responder-transport'
import { Request } from './request'

interface HttpSubjectData<T extends Request = Request> {
  req: T
  httpRes: http.ServerResponse
}

export class HttpResponderTransport extends ResponderTransport {
  rpcSubject: Subject<HttpSubjectData>

  constructor (protected server: http.Server, opts?: Partial<ResponderOptions>) {
    super(opts)
    this.rpcSubject = new Subject()
    this.server.on('request', (req, res) => {
      this.onRequest(req, res).catch((err) => {
        throw err // TODO: Handle exception?
      })
    })
  }

  async onRequest (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (this.isPairing && req.method === 'POST') {
      switch (req.url) {
        case `/${constants.RPC_URL_PATH}`:
        {
          const buffers = []

          for await (const chunk of req) {
            buffers.push(chunk)
          }

          const data = Buffer.concat(buffers).toString()
          const reqBody = JSON.parse(data)
          this.rpcSubject.next({ req: reqBody, httpRes: res })
          return
        }
      }
    }

    res.writeHead(404)
    res.end()
  }

  async waitRequest<M extends Request['method'], T extends (Request & { method: M})> (method: M): Promise<HttpSubjectData<T>> {
    while (true) {
      const rpcRequest = await this.rpcSubject.promise
      if (rpcRequest.req.method !== method) {
        continue
      }

      return rpcRequest as HttpSubjectData<T>
    }
  }

  async sendResponse (httpRes: http.ServerResponse, req: Request): Promise<void> {
    httpRes.write(JSON.stringify(req))
    httpRes.end()
  }

  async publicKeyExchange (protocol: WalletProtocol, pkeData: PKEData): Promise<ProtocolPKEData> {
    if (this.connString === undefined) {
      throw new Error('protocol not properly initialized')
    }

    const { req, httpRes } = await this.waitRequest('publicKeyExchange')
    await this.sendResponse(httpRes, {
      method: 'publicKeyExchange',
      sender: pkeData.id,
      publicKey: pkeData.publicKey
    })

    const received: PKEData = {
      id: req.sender,
      publicKey: req.publicKey,
      rx: format.base642u8Arr(req.ra ?? '')
    }

    return {
      a: received,
      b: pkeData,

      sent: pkeData,
      received
    }
  }

  async authentication (protocol: WalletProtocol, authData: AuthData): Promise<ProtocolAuthData> {
    const cxHttpData = await this.waitRequest('commitment')
    await this.sendResponse(cxHttpData.httpRes, {
      method: 'commitment',
      cx: format.u8Arr2Base64(authData.cx)
    })
    const commitmentReq = cxHttpData.req

    const nxHttpData = await this.waitRequest('nonce')
    await this.sendResponse(nxHttpData.httpRes, {
      method: 'nonce',
      nx: format.u8Arr2Base64(authData.nx)
    })
    const nonceReq = nxHttpData.req

    const received: AuthData = {
      cx: format.base642u8Arr(commitmentReq.cx),
      nx: format.base642u8Arr(nonceReq.nx),
      r: authData.r
    }

    return {
      a: received,
      b: authData,

      sent: authData,
      received
    }
  }

  async finish (): Promise<void> {
    super.finish()
    this.rpcSubject.err('Finished')
    console.log('finish')
  }
}
