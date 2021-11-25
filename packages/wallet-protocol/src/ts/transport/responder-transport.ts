import { ConnectionString, constants, Identity, WalletProtocol, PKEData } from '../internal'
import { BaseTransport } from './transport'

export interface ResponderOptions {
  port: number
  timeout: number
  id: Identity
  l: number
}

export abstract class ResponderTransport extends BaseTransport {
  protected opts: ResponderOptions

  protected lastPairing: NodeJS.Timeout | undefined

  // Protocol Data
  public connString: ConnectionString | undefined

  constructor (opts: Partial<ResponderOptions> = {}) {
    super()
    this.opts = {
      port: opts.port ?? constants.INITIAL_PORT,
      timeout: opts.timeout ?? constants.DEFAULT_TIMEOUT,
      id: opts.id ?? { name: 'Responder' },
      l: opts.l ?? constants.DEFAULT_RANDOM_LENGTH
    }
  }

  async pairing (port: number, timeout: number): Promise<void> {
    this.stopPairing()

    this.connString = await ConnectionString.generate(port, this.opts.l)
    this.lastPairing = setTimeout(() => {
      this.stopPairing()
      this.finish()
    }, timeout)
  }

  stopPairing (): void {
    if (this.lastPairing != null) {
      console.log('stop pairing')
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
    await this.pairing(this.port, this.timeout)
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

  finish (): void {
    this.stopPairing()
    this.connString = undefined
  }
}
