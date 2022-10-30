import { ethers } from 'ethers'
/**
 * Verifies and returns an ethereum address
 * @param a
 * @returns
 */
export function parseAddress (a: string): string {
  const hexMatch = a.match(/^(0x)?([\da-fA-F]{40})$/)
  if (hexMatch == null) {
    throw new RangeError('incorrect address format')
  }
  const hex = hexMatch[2]
  return ethers.utils.getAddress('0x' + hex)
}
