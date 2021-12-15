import { NrError } from '../errors'

export function parseHex (a: string, prefix0x: boolean = false): string {
  const hexMatch = a.match(/^(0x)?([\da-fA-F]+)$/)
  if (hexMatch == null) {
    throw new NrError(new RangeError('input must be a hexadecimal string, e.g. \'0x124fe3a\' or \'0214f1b2\''), ['invalid format'])
  }
  const hex = hexMatch[2].toLocaleLowerCase()
  return (prefix0x) ? '0x' + hex : hex
}
