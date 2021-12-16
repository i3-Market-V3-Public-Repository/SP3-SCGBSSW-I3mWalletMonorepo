import {
  ConnectionString,
  constants,
  Identity,
  WalletProtocol,
  random,
  PKEData,
  ProtocolPKEData,
  format,
  AuthData,
  MasterKey,
  ProtocolAuthData
} from '../internal'
import { BaseTransport } from './transport'
import { CommitmentRequest, NonceRevealRequest, PublicKeyExchangeRequest, Request, VerificationChallengeRequest } from './request'

export interface InitiatorOptions {
  host: string
  id: Identity
  l: number
  getConnectionString: () => Promise<string>
}

export abstract class InitiatorTransport<Req, Res> extends BaseTransport<Req, Res> {
  protected opts: InitiatorOptions

  // Protocol Data
  public connString: ConnectionString | undefined

  constructor (opts: Partial<InitiatorOptions> = {}) {
    super()
    this.opts = {
      host: opts.host ?? 'localhost',
      id: opts.id ?? { name: 'Initiator' },
      l: opts.l ?? constants.DEFAULT_RANDOM_LENGTH,
      getConnectionString: opts.getConnectionString ?? (async (): Promise<string> => {
        throw new Error('getConnectionString must be provided')
      })
    }
  }

  abstract sendRequest<T extends Request> (request: Request): Promise<T>

  async prepare (protocol: WalletProtocol, publicKey: string): Promise<PKEData> {
    const connString = await this.opts.getConnectionString()
    if (connString === '') {
      throw new Error('empty connection string')
    }
    this.connString = ConnectionString.fromString(connString, this.opts.l)

    const lLen = Math.ceil(this.opts.l / 8)
    const ra = new Uint8Array(lLen)
    await random.randomFillBits(ra, 0, this.opts.l)

    return {
      id: this.opts.id,
      publicKey,
      rx: ra
    }
  }

  async publicKeyExchange (protocol: WalletProtocol, pkeData: PKEData): Promise<ProtocolPKEData> {
    if (this.connString === undefined) {
      throw new Error('missing connection string')
    }

    const response = await this.sendRequest<PublicKeyExchangeRequest>({
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

      port: this.connString.extractPort(),
      sent: pkeData,
      received
    }
  }

  async authentication (protocol: WalletProtocol, authData: AuthData): Promise<ProtocolAuthData> {
    const commitmentReq = await this.sendRequest<CommitmentRequest>({
      method: 'commitment',
      cx: format.u8Arr2Base64(authData.cx)
    })

    const nonceReq = await this.sendRequest<NonceRevealRequest>({
      method: 'nonce',
      nx: format.u8Arr2Base64(authData.nx)
    })
    const received: AuthData = {
      cx: format.base642U8Arr(commitmentReq.cx),
      nx: format.base642U8Arr(nonceReq.nx),
      r: authData.r
    }

    return {
      a: authData,
      b: {
        cx: format.base642U8Arr(commitmentReq.cx),
        nx: format.base642U8Arr(nonceReq.nx),
        r: authData.r
      },

      sent: authData,
      received
    }
  }

  async verification (protocol: WalletProtocol, masterKey: MasterKey): Promise<Uint8Array> {
    const verifChallenge = await this.sendRequest<VerificationChallengeRequest>({
      method: 'verification'
    })

    const inCiphertext = format.base642U8Arr(verifChallenge.ciphertext)
    const code = await masterKey.decrypt(inCiphertext)
    return code
  }

  finish (protocol: WalletProtocol): void {
    super.finish(protocol)
    this.connString = undefined
  }
}
