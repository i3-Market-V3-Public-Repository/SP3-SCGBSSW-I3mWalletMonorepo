import {
  ConnectionString,
  constants,
  Identity,
  WalletProtocol,
  PKEData,
  Subject,
  format,
  AuthData,
  MasterKey,
  ProtocolAuthData,
  ProtocolPKEData,
  CodeGenerator,
  defaultCodeGenerator
} from '../internal'
import { BaseTransport } from './transport'
import { Request } from './request'
import { Response } from './response'

export interface ResponderOptions {
  port: number
  timeout: number
  id: Identity
  l: number
  codeGenerator: CodeGenerator
}

interface SubjectData<T extends Request = Request, S extends Request = Request> {
  req: T
  res: Response<S>
}

export abstract class ResponderTransport<Req, Res> extends BaseTransport<Req, Res> {
  protected opts: ResponderOptions
  protected rpcSubject: Subject<SubjectData>

  protected lastPairing: NodeJS.Timeout | undefined

  // Protocol Data
  public connString: ConnectionString | undefined

  constructor (opts: Partial<ResponderOptions> = {}) {
    super()
    this.opts = {
      port: opts.port ?? constants.INITIAL_PORT,
      timeout: opts.timeout ?? constants.DEFAULT_TIMEOUT,
      id: opts.id ?? { name: 'Responder' },
      l: opts.l ?? constants.DEFAULT_RANDOM_LENGTH,
      codeGenerator: opts.codeGenerator ?? defaultCodeGenerator
    }
    this.rpcSubject = new Subject()
  }

  async pairing (protocol: WalletProtocol, port: number, timeout: number): Promise<void> {
    this.stopPairing()

    this.connString = await ConnectionString.generate(port, this.opts.l)
    this.lastPairing = setTimeout(() => {
      this.stopPairing()
      this.finish(protocol)
    }, timeout)
  }

  stopPairing (): void {
    if (this.lastPairing != null) {
      clearTimeout(this.lastPairing)
      this.lastPairing = undefined
    }
  }

  get isPairing (): boolean {
    return this.connString !== undefined
  }

  get port (): number {
    return this.opts.port
  }

  get timeout (): number {
    return this.opts.timeout
  }

  async prepare (protocol: WalletProtocol, publicKey: string): Promise<PKEData> {
    await this.pairing(protocol, this.port, this.timeout)
    if (this.connString === null || this.connString === undefined) {
      throw new Error('could not generate connection string')
    }

    protocol.emit('connString', this.connString)

    return {
      id: this.opts.id,
      publicKey,
      rx: this.connString.extractRb()
    }
  }

  async waitRequest<M extends Request['method'], T extends (Request & { method: M})> (method: M): Promise<SubjectData<T>> {
    while (true) {
      const rpcRequest = await this.rpcSubject.promise
      if (rpcRequest.req.method !== method) {
        continue
      }

      return rpcRequest as SubjectData<T>
    }
  }

  async publicKeyExchange (protocol: WalletProtocol, pkeData: PKEData): Promise<ProtocolPKEData> {
    if (this.connString === undefined) {
      throw new Error('protocol not properly initialized')
    }

    const { req, res } = await this.waitRequest('publicKeyExchange')
    await res.send({
      method: 'publicKeyExchange',
      sender: pkeData.id,
      publicKey: pkeData.publicKey
    })

    const received: PKEData = {
      id: req.sender,
      publicKey: req.publicKey,
      rx: format.base642U8Arr(req.ra ?? '')
    }

    return {
      a: received,
      b: pkeData,

      sent: pkeData,
      received
    }
  }

  async authentication (protocol: WalletProtocol, authData: AuthData): Promise<ProtocolAuthData> {
    const cxData = await this.waitRequest('commitment')
    await cxData.res.send({
      method: 'commitment',
      cx: format.u8Arr2Base64(authData.cx)
    })
    const commitmentReq = cxData.req

    const nxData = await this.waitRequest('nonce')
    await nxData.res.send({
      method: 'nonce',
      nx: format.u8Arr2Base64(authData.nx)
    })
    const nonceReq = nxData.req

    const received: AuthData = {
      cx: format.base642U8Arr(commitmentReq.cx),
      nx: format.base642U8Arr(nonceReq.nx),
      r: authData.r
    }

    return {
      a: received,
      b: authData,

      sent: authData,
      received
    }
  }

  async verification (protocol: WalletProtocol, masterKey: MasterKey): Promise<Uint8Array> {
    const verifData = await this.waitRequest('verification')
    const code = await this.opts.codeGenerator.generate(masterKey)
    const ciphertext = await masterKey.encrypt(code)
    await verifData.res.send({
      method: 'verificationChallenge',
      ciphertext: format.u8Arr2Base64(ciphertext)
    })

    return code
  }

  finish (protocol: WalletProtocol): void {
    super.finish(protocol)
    this.stopPairing()
    // TODO: When has error??
    this.rpcSubject.err('Finished')
    this.connString = undefined
  }
}
