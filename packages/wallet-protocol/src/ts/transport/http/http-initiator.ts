import { WalletProtocol, format, ProtocolPKEData, constants, AuthData, PKEData, ProtocolAuthData } from '../../internal'
import { InitiatorTransport } from '../initiator-transport'
import { Request } from './request'

export class HttpInitiatorTransport extends InitiatorTransport {
  get rpcUrl (): string {
    if (this.connString === undefined) {
      throw new Error('cannot connect to the rpc yet: port missing')
    }

    return `http://${this.opts.host}:${this.connString.extractPort()}/${constants.RPC_URL_PATH}`
  }

  async sendRequest<T extends Request> (request: T): Promise<T> {
    const resp = await fetch(this.rpcUrl, {
      method: 'POST',
      body: JSON.stringify(request)
    })
    const body: T = await resp.json()

    return body
  }

  async publicKeyExchange (protocol: WalletProtocol, pkeData: PKEData): Promise<ProtocolPKEData> {
    if (this.connString === undefined) {
      throw new Error('missing connection string')
    }

    const response = await this.sendRequest({
      method: 'publicKeyExchange',
      sender: this.opts.id,
      publicKey: pkeData.publicKey,
      ra: format.u8Arr2Base64(pkeData.rx)
    })

    const received: PKEData = {
      id: response.sender,
      publicKey: response.publicKey,
      rx: this.connString.extractRb()
    }

    return {
      a: pkeData,
      b: received,

      sent: pkeData,
      received
    }
  }

  async authentication (protocol: WalletProtocol, authData: AuthData): Promise<ProtocolAuthData> {
    const commitmentReq = await this.sendRequest({
      method: 'commitment',
      cx: format.u8Arr2Base64(authData.cx)
    })

    const nonceReq = await this.sendRequest({
      method: 'nonce',
      nx: format.u8Arr2Base64(authData.nx)
    })
    const received: AuthData = {
      cx: format.base642u8Arr(commitmentReq.cx),
      nx: format.base642u8Arr(nonceReq.nx),
      r: authData.r
    }

    return {
      a: authData,
      b: {
        cx: format.base642u8Arr(commitmentReq.cx),
        nx: format.base642u8Arr(nonceReq.nx),
        r: authData.r
      },

      sent: authData,
      received
    }
  }
}
