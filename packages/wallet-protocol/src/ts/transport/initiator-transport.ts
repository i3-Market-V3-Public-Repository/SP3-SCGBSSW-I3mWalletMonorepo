import { ConnectionString, constants, Identity, WalletProtocol, random, PKEData } from '../internal'
import { BaseTransport } from './transport'

export interface InitiatorOptions {
  host: string
  id: Identity
  l: number
  getConnectionString: () => Promise<string>
}

export abstract class InitiatorTransport extends BaseTransport {
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

  async prepare (protocol: WalletProtocol, publicKey: string): Promise<PKEData> {
    const connString = await this.opts.getConnectionString()
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

  finish (): void {
    this.connString = undefined
  }
}
