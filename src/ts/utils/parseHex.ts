import { NrError } from '../errors'

export function parseHex (a: string, prefix0x: boolean = false, byteLength?: number): string {
  const hexMatch = a.match(/^(0x)?(([\da-fA-F][\da-fA-F])+)$/)
  if (hexMatch == null) {
    throw new NrError(new RangeError('input must be a hexadecimal string, e.g. \'0x124fe3a\' or \'0214f1b2\''), ['invalid format'])
  }
  let hex = hexMatch[2]
  if (byteLength !== undefined) {
    if (byteLength < hex.length / 2) {
      throw new NrError(new RangeError(`expected byte length ${byteLength} < input hex byte length ${Math.ceil(hex.length / 2)}`), ['invalid format'])
    }
    hex = hex.padStart(byteLength * 2, '0')
  }
  return (prefix0x) ? '0x' + hex : hex
}
