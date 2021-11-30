import { format, Transport, TransportRequest, TransportResponse } from '../internal'
import { MasterKey } from './master-key'

export class Session<T extends Transport> {
  constructor (protected transport: T, protected masterKey: MasterKey, protected code: Uint8Array) {}

  async send (request: TransportRequest<T>): Promise<TransportResponse<T>> {
    return await this.transport.send(this.masterKey, this.code, request)
  }

  toJSON (): any {
    return {
      masterKey: this.masterKey.toJSON(),
      code: format.u8Arr2Hex(this.code)
    }
  }

  static async fromJSON <T extends Transport>(transport: T, json: any): Promise<Session<T>> {
    const masterKey = await MasterKey.fromJSON(json.masterKey)
    const code = format.hex2U8Arr(json.code)

    return new Session(transport, masterKey, code)
  }
}
