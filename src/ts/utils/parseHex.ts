import { parseHex as bcParseHex } from 'bigint-conversion'
import { NrError } from '../errors/index.js'

export function parseHex (a: string, prefix0x: boolean = false, byteLength?: number): string {
  try {
    return bcParseHex(a, prefix0x, byteLength)
  } catch (error) {
    throw new NrError(error, ['invalid format'])
  }
}
