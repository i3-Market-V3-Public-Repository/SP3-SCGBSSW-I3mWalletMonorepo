/**
 * Verifies an hexadecimal string and returns it with (default) or without 0x prefix
 * @param a
 * @param prefix0x
 * @returns
 */
export function parseHex (a: string, prefix0x: boolean = true): string {
  const hexMatch = a.match(/^(0x)?(([\da-fA-F][\da-fA-F])+)$/)
  if (hexMatch == null) {
    throw new RangeError('wrong hex input')
  }
  const hex = hexMatch[2]
  return (prefix0x) ? '0x' + hex : hex
}
