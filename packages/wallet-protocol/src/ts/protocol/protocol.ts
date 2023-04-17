import pbkdf2Hmac from 'pbkdf2-hmac'
import * as objectSha from 'object-sha'

import {
  Transport,
  ECDH,
  ConnectionString,
  random,
  constants,
  format,
  digest,
  bufferUtils,
  InvalidPinError
} from '../internal'
import { EventEmitter } from './event-emitter'
import { AuthData, ProtocolAuthData, ProtocolPKEData } from './state'
import { MasterKey } from './master-key'
import { Session } from './session'

export class WalletProtocol<T extends Transport = Transport> extends EventEmitter {
  constructor (public transport: T) {
    super()
  }

  async computeR (ra: Uint8Array, rb: Uint8Array): Promise<Uint8Array> {
    return ra.map((val, i) => val ^ rb[i])
  }

  async computeNx (): Promise<Uint8Array> {
    const nLen = Math.ceil(constants.NONCE_LENGTH / 8)
    const nx = new Uint8Array(nLen)

    await random.randomFillBits(nx, 0, constants.NONCE_LENGTH)
    return nx
  }

  async computeCx (pkeData: ProtocolPKEData, nx: Uint8Array, r: Uint8Array): Promise<Uint8Array> {
    const nLen = Math.ceil(constants.NONCE_LENGTH / 8)
    const rLen = Math.ceil(constants.DEFAULT_RANDOM_LENGTH / 8)
    const pka = format.hex2U8Arr(pkeData.a.publicKey)
    const pkb = format.hex2U8Arr(pkeData.b.publicKey)

    const inputLen = 2 * 32 + nLen + rLen
    const input = new Uint8Array(inputLen)

    // Build input data
    // TODO: change format?
    bufferUtils.insertBytes(pka, input, 1, 0, 32)
    bufferUtils.insertBytes(pkb, input, 1, 32, 32)
    bufferUtils.insertBits(nx, input, 0, 2 * 32 * 8, constants.NONCE_LENGTH)
    bufferUtils.insertBits(r, input, 0, 2 * 32 * 8 + constants.NONCE_LENGTH, constants.DEFAULT_RANDOM_LENGTH)

    // Compute hash
    const hash = await digest.digest('sha256', input)
    return hash
  }

  async validateAuthData (fullPkeData: ProtocolPKEData, fullAuthData: ProtocolAuthData): Promise<void> {
    const { cx: receivedCx, nx: receivedNx } = fullAuthData.received
    const { cx: sentCx, nx: sentNx, r } = fullAuthData.sent

    // Check valid lengths
    const validLengths = receivedCx.length === sentCx.length &&
      receivedNx.length === sentNx.length
    if (!validLengths) {
      throw new InvalidPinError('invalid received auth data length')
    }

    // Check different Cx
    const equalCx = receivedCx.every((byte, i) => byte === sentCx[i])
    if (equalCx) {
      throw new InvalidPinError('received and sent Cx are the same')
    }

    // Check valid Cx
    const expectedCx = await this.computeCx(fullPkeData, receivedNx, r)
    const validCx = expectedCx.every((byte, i) => byte === receivedCx[i])
    if (!validCx) {
      throw new InvalidPinError('received a wrong Cx')
    }
  }

  async computeMasterKey (ecdh: ECDH, fullPkeData: ProtocolPKEData, fullAuthData: ProtocolAuthData): Promise<MasterKey> {
    const nLen = Math.ceil(constants.NONCE_LENGTH / 8)

    // Prepare data
    const sharedSecret = await ecdh.deriveBits(fullPkeData.received.publicKey)
    const salt = new Uint8Array(16)
    const secretWithContext = new Uint8Array(32 + 2 * nLen + 6 + 32 * 2)
    const masterContext = new Uint8Array([109, 97, 115, 116, 101, 114]) // 'master' in UTF-8
    const aHash = await objectSha.digest(fullPkeData.a, 'SHA-256')
    const aHashBuffer = format.hex2U8Arr(aHash)
    const bHash = await objectSha.digest(fullPkeData.b, 'SHA-256')
    const bHashBuffer = format.hex2U8Arr(bHash)

    // Prepare input
    bufferUtils.insertBytes(sharedSecret, secretWithContext, 0, 0, 32)
    bufferUtils.insertBytes(fullAuthData.a.nx, secretWithContext, 0, 32, nLen)
    bufferUtils.insertBytes(fullAuthData.a.nx, secretWithContext, 0, 32 + nLen, nLen)
    bufferUtils.insertBytes(masterContext, secretWithContext, 0, 32 + 2 * nLen, 6)
    bufferUtils.insertBytes(aHashBuffer, secretWithContext, 0, 32 + 2 * nLen + 6, 32)
    bufferUtils.insertBytes(bHashBuffer, secretWithContext, 0, 32 + 2 * nLen + 6 + 32, 32)

    // Compute master key
    const secret = await pbkdf2Hmac(secretWithContext, salt, 1, 32)
    const masterKey = await MasterKey.fromSecret(
      fullPkeData.port,
      fullPkeData.sent.id,
      fullPkeData.received.id,
      fullAuthData.a.nx,
      fullAuthData.b.nx,
      new Uint8Array(secret)
    )
    return masterKey
  }

  async run (): Promise<Session<T>> {
    const _run = async (): Promise<Session<T>> => {
      // Initial protocol preparation
      const ecdh = new ECDH()
      await ecdh.generateKeys()
      const publicKey = await ecdh.getPublicKey()

      // Prepare public key exchange
      const pkeData = await this.transport.prepare(this, publicKey)

      // Perform public key exchange
      let fullPkeData: ProtocolPKEData
      try {
        fullPkeData = await this.transport.publicKeyExchange(this, pkeData)
      } catch (err) {
        if (err instanceof TypeError) {
          throw new InvalidPinError(err.message)
        }
        throw err
      }

      // Prepare authenticate
      const r = await this.computeR(fullPkeData.a.rx, fullPkeData.b.rx)
      const nx = await this.computeNx()
      const cx = await this.computeCx(fullPkeData, nx, r)
      const authData: AuthData = { r, nx, cx }

      // Perform authenticate
      const fullAuthData = await this.transport.authentication(this, authData)

      // Verify authentication
      await this.validateAuthData(fullPkeData, fullAuthData)

      // Generate master key
      const masterKey = await this.computeMasterKey(ecdh, fullPkeData, fullAuthData)
      const code = await this.transport.verification(this, masterKey)

      //
      const session = new Session(this.transport, masterKey, code)
      this.emit('masterKey', masterKey)

      return session
    }

    return await _run().finally(() => {
      this.transport.finish(this)
    })
  }

  on (event: 'connString', listener: (connString: ConnectionString) => void): this
  on (event: 'masterKey', listener: (masterKey: MasterKey) => void): this
  on (event: 'finished', listener: () => void): this
  on (event: string, listener: (...args: any[]) => void): this {
    return super.on(event, listener)
  }

  emit (event: 'connString', connString: ConnectionString): boolean
  emit (event: 'masterKey', masterKey: MasterKey): boolean
  emit (event: 'finished'): boolean
  emit (event: string, ...args: any[]): boolean {
    return super.emit(event, ...args)
  }
}
