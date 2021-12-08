export function parseHex (a: string): string {
  const hexMatch = a.match(/^(0x)?([\da-fA-F]+)$/)
  if (hexMatch == null) {
    throw RangeError('input must be a hexadecimal string, e.g. \'0x124fe3a\' or \'0214f1b2\'')
  }

  return hexMatch[2].toLocaleLowerCase()
}
